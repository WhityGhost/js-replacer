extern crate swc_ecma_parser;
extern crate swc_ecma_ast;
extern crate swc_ecma_visit;
extern crate swc_common;
extern crate regex;

use neon::prelude::*;
use swc_common::{BytePos, FileName, SourceFile};
use std::fs;
use std::io::Write;
use std::{fs::File, sync::Arc};
use std::collections::HashSet;
use swc_common::{sync::Lrc, SourceMap, Spanned, source_map::Pos};
use swc_ecma_parser::{Parser, StringInput, lexer::Lexer, EsSyntax};
use swc_ecma_ast::*;
use swc_ecma_visit::{Visit, VisitWith};
use regex::Regex;

mod this_helper {
    pub const LOCATION_STR: &str = "location";
    pub const MCOP_LOCATION_STR: &str = "__mcopLocation";
    pub const MCOP_FUNC1_NAME: &str = "_mcopPreparePostMessageMsg";
    pub const MCOP_FUNC2_NAME: &str = "_mcopPreparePostMessageOrigin";
    pub const POST_MESSAGE_NAME: &str = "postMessage";
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("replace_js_code", replace_js_code)?;
    cx.export_function("read_file_to_string", read_file_to_string)?;
    Ok(())
}

fn read_file_to_string(mut cx: FunctionContext) -> JsResult<JsString> {
    let path_prm = cx.argument::<JsString>(0)?;
    let path_str = path_prm.value(&mut cx).to_string();
    let contents = fs::read_to_string(path_str)
        .expect("Error: Unable to read the file.");
    Ok(cx.string(contents))
}

fn replace_js_code(mut cx: FunctionContext) -> JsResult<JsString> {
    let raw_js_prm = cx.argument::<JsString>(0)?;
    let raw_js_str = raw_js_prm.value(&mut cx).to_string();
    
    let source_file = SourceFile::new(
        FileName::Custom("input.js".into()),
        false,
        FileName::Custom("input.js".into()),
        raw_js_str.clone(),
        BytePos::from_usize(0)
    );
    let rc_source_file = Lrc::new(source_file);

    let string_input = StringInput::from(&*rc_source_file);

    let lexer = Lexer::new(
        swc_ecma_parser::Syntax::Es(EsSyntax { ..Default::default() }),
        EsVersion::Es2020,
        string_input,
        None);
    
    let mut parser = Parser::new_from(lexer);

    let start_time = std::time::Instant::now();

    let module = match parser.parse_module() {
        Ok(module) => {
            module
        }
        Err(err) => panic!("Failed to parse JavaScript code: {:?}", err),
    };
    
    let _transformed_module = transform_js_module(module, raw_js_str.clone());
    let end_time = std::time::Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    println!("Operation completed in {:?}", elapsed_time);
    Ok(cx.string(_transformed_module))
}

fn transform_js_module(module: Module, raw: String) -> String {
    let mut loc_visitor: ReplaceLocationVisitor = ReplaceLocationVisitor::new(raw.clone());
    // println!("{:?}", raw.find("location.origin+\"/api/startupUserData\",yP=").take());
    loc_visitor.visit_module(&module);
    loc_visitor.commit_replacements();
    let res_raw = loc_visitor.jscode_new;
    return res_raw
}

fn find_all_occurrences(subject: &str, input_str: &str) -> Vec<usize> {
    let mut occurrences = Vec::new();
    let mut previous_index = 0;

    while let Some(index) = input_str[previous_index..].find(subject) {
        let absolute_index = previous_index + index;
        occurrences.push(absolute_index);
        previous_index = absolute_index + subject.len();
    }
    occurrences
}

struct ReplaceLocationVisitor {
    jscode_raw: String,
    jscode_new: String,
    replacements: Vec<Replacement>,
    allowed_chars_regexp: Regex,
    skipped_strings: HashSet<Replacement>,
    processed_member_nodes: Vec<Replacement>,
    processed_callee_nodes: Vec<Replacement>,
    delta: usize,
}

impl ReplaceLocationVisitor {
    fn new(raw: String) -> Self {
        ReplaceLocationVisitor {
            jscode_raw: raw.clone(),
            jscode_new: raw.clone(),
            replacements: vec![],
            allowed_chars_regexp: Regex::new(r"[.=\s,;():?\[\]+\-{}&|!>\n\r]").expect("Invalid regex pattern"),
            skipped_strings: HashSet::new(),
            processed_member_nodes: Vec::new(),
            processed_callee_nodes: Vec::new(),
            delta: 0
        }
    }

    fn looks_like_url(s: &str) -> bool {
        let matches = s.matches('/').count();
        let no_illegal_char = !s.chars().any(|c| c.is_whitespace() || c == '\'' || c == '"' || c == '\\');
        
        (matches > 0 && no_illegal_char) || (matches > 0 && s.contains('.')) && no_illegal_char
    }

    fn looks_like_css(s: &str) -> bool {
        let reg_exp = Regex::new(r#"[a-z0-9-_:\\s]+location|[a-z0-9-_:\\s]?+location[\s:_]?+[a-z0-9-_:\\s]+"#).unwrap();
        reg_exp.is_match(s)
    }

    fn looks_like_classname(s: &str) -> bool {
        let reg_exp = Regex::new(r#"[a-z0-9-_\.]+location[a-z0-9-_\.]+"#).unwrap();
        reg_exp.is_match(s)
    }

    fn add_str_to_list(&mut self, s: Replacement) {
        if !self.skipped_strings.iter().any(|item| item.start == s.start && item.end == s.end) {
            self.skipped_strings.insert(s);
        }
    }

    fn contains_skipped_str(&self, start: usize, end: usize) -> bool {
        self.skipped_strings.iter().any(|item| start > item.start && end < item.end)
    }

    fn contains_skipped_call(&self, start: usize, end: usize) -> bool {
        self.processed_callee_nodes.iter().any(|item| start < item.start && end > item.end)
    }

    fn contains_skipped_member(&self, start: usize, end: usize) -> bool {
        self.processed_member_nodes.iter().any(|item| start < item.start && end > item.end)
    }

    fn can_location_be_replaced_in_member_expression(&self, node_start: usize, node_end: usize) -> bool {
        let snippet = &self.jscode_raw[node_start..node_end];
        
        if let Some(matched) = snippet.match_indices(&this_helper::LOCATION_STR).next() {
            let start = node_start + matched.0;
            let end: usize = start + this_helper::LOCATION_STR.len();
            let char_before = if start > 0 {&self.jscode_raw[start - 1..start]} else {""};
            let char_after = if end < self.jscode_raw.len() {&self.jscode_raw[end..end + 1]} else {""};
    
            let test1 = char_before.is_empty() || self.allowed_chars_regexp.is_match(&char_before);
            let test2 = char_after.is_empty() || self.allowed_chars_regexp.is_match(&char_after);

            return test1 && test2;
        }
    
        false  
    }

    fn replace_location_in_property(&self, parent_node: Prop, js_code: &str, is_key: bool) -> Vec<Replacement> {
        // let parent_start = parent_node.span_lo().to_usize() - 1;
        let node_start: usize;
        let node_end: usize;
        let node_is_lit;
        if is_key {
            if let Prop::KeyValue(KeyValueProp { key, .. }) = parent_node {
                node_start = key.span_lo().to_usize() - 1;
                node_end = key.span_hi().to_usize() - 1;
            } else {
                node_start = 0;
                node_end = 0;
                println!("Not a Key KeyValueProp");
            }
            node_is_lit = false;
        } else {
            if let Prop::KeyValue(KeyValueProp { value, .. }) = parent_node {
                node_start = value.span_lo().to_usize() - 1;
                node_end = value.span_hi().to_usize() - 1;
                node_is_lit = value.is_lit();
            } else {
                node_start = 0;
                node_end = 0;
                println!("Not a Value KeyValueProp");
                node_is_lit = false;
            }
        }
        let snippet = &js_code[node_start..node_end];

        let mut result: Vec<Replacement> = vec![];
        
        if Self::looks_like_url(snippet) {
            return result;
        }
    
        let char_before = if node_start > 0 {&self.jscode_raw[node_start - 1..node_start]} else {""};
        let char_after = if node_end < self.jscode_raw.len() {&self.jscode_raw[node_end..node_end + 1]} else {""};
        
        let test0 = node_is_lit && snippet.replace(&['\'', '"'][..], "").replace(&this_helper::LOCATION_STR, "").is_empty();

        let test1 = char_before.is_empty() || self.allowed_chars_regexp.is_match(&char_before);
        let test2 = char_after.is_empty() || self.allowed_chars_regexp.is_match(&char_after);
    
        if test0 || (test1 && test2) {
            let re = Regex::new(this_helper::LOCATION_STR).unwrap();
            let matches: Vec<(&str, usize, usize)> = re.find_iter(snippet)
                .map(|mat| (mat.as_str(), mat.start(), mat.end())).collect();
            for (_mat, start, end) in matches {
                let char_before_mat = if start > 0 {&snippet[start - 1..start]} else {""};
                let char_after_mat = if end < snippet.len() {&snippet[end..end + 1]} else {""};

                let contained_by_lit = self.contains_skipped_str(node_start + start, node_start + end);
        
                let char_before_is_fine = char_before_mat.is_empty()
                    || self.allowed_chars_regexp.is_match(&char_before_mat);
                let char_after_is_fine = char_after_mat.is_empty()
                    || self.allowed_chars_regexp.is_match(&char_after_mat);

                let surround_is_fine = (char_before_is_fine && char_after_is_fine)
                    || (char_before_mat == "\"" && char_after_mat == "\"")
                    || (char_before_mat == "\'" && char_after_mat == "\'");

                if surround_is_fine && !contained_by_lit {
                    result.insert(result.len(), Replacement::new(
                        node_start + start,
                        node_start + end,
                        this_helper::MCOP_LOCATION_STR.to_string()
                    ));
                }
            }
        }
        result
    }

    fn is_literal_or_looks_like_url_or_css(&self, js_code: &str) -> bool {
        return Self::looks_like_css(js_code) || Self::looks_like_url(js_code) || Self::looks_like_classname(js_code);
    }
    
    fn commit_replacements(&mut self) {
        self.replacements.sort_by(|a, b| a.start.cmp(&b.start));
        let mut buffer: Replacement = Replacement::new(0, 0, "".to_string());

        for rplmnt in &self.replacements {
            if buffer.start == rplmnt.start && buffer.end == rplmnt.end {
                continue;
            }
            else if buffer.start <= rplmnt.start && buffer.end >= rplmnt.end {
                let snippet = &self.jscode_new[rplmnt.start + self.delta..rplmnt.end + self.delta];
                buffer.to = buffer.to.replace(snippet, &rplmnt.to);
            } else {
                let snippet = &self.jscode_new[buffer.start + self.delta..buffer.end + self.delta];
                if snippet.contains(this_helper::LOCATION_STR) || snippet.contains(this_helper::POST_MESSAGE_NAME) {
                    self.jscode_new.replace_range(buffer.start + self.delta..buffer.end + self.delta, buffer.to.as_str());
                    self.delta += buffer.to.len() - buffer.end + buffer.start;
                }
                buffer = Replacement::from(rplmnt);
            }
        }
        let snippet = &self.jscode_new[buffer.start + self.delta..buffer.end + self.delta];
        if snippet.contains(this_helper::LOCATION_STR) || snippet.contains(this_helper::POST_MESSAGE_NAME) {
            self.jscode_new.replace_range(buffer.start + self.delta..buffer.end + self.delta, buffer.to.as_str());
            self.delta += buffer.to.len() - buffer.end + buffer.start;
        }
    }

    fn remove_newlines(str: &str) -> String {
        if Regex::new(r"void\s+").unwrap().is_match(str) {
            return str.to_owned();
        }
        Regex::new(r"[\n\s]").unwrap().replace_all(str, "").to_string()
    }

    fn build_arguments_part(&self, args: &Vec<ExprOrSpread>) -> String {
        if !args.is_empty() && args.len() >= 1 && args.len() <= 3 {
            match args.len() {
                1 => {
                    let arg1_part = Self::remove_newlines(&self.jscode_raw[args[0].span_lo().to_usize() - 1..args[0].span_hi().to_usize() - 1]);
                    if args[0].expr.is_seq() {
                        format!("{}(({}))", this_helper::MCOP_FUNC1_NAME, arg1_part)
                    } else {
                        format!("{}({})", this_helper::MCOP_FUNC1_NAME, arg1_part)
                    }
                },
                2 => {
                    let mut arguments_part = self.build_arguments_part(&vec![args[0].clone()]);
                    let arg2_part = Self::remove_newlines(&self.jscode_raw[args[1].span_lo().to_usize() - 1..args[1].span_hi().to_usize() - 1]);
                    if args[1].expr.is_seq() {
                        arguments_part.push_str(&format!("{}(({}))", this_helper::MCOP_FUNC2_NAME, arg2_part));
                    } else {
                        arguments_part.push_str(&format!(",{}({})", this_helper::MCOP_FUNC2_NAME, arg2_part));
                    }
                    arguments_part
                },
                3 => {
                    let mut arguments_part = self.build_arguments_part(&vec![args[0].clone(), args[1].clone()]);
                    let arg3_part = Self::remove_newlines(&self.jscode_raw[args[2].span_lo().to_usize() - 1..args[2].span_hi().to_usize() - 1]);
                    if args[2].expr.is_seq() {
                        arguments_part.push_str(&format!(",(({}))", arg3_part));
                    } else {
                        arguments_part.push_str(&format!(",{}", arg3_part));
                    }
                    arguments_part
                },
                _ => String::new(),
            }
        } else {
            String::new()
        }
    }
}

impl Visit for ReplaceLocationVisitor {
    fn visit_lit(&mut self, literal: &Lit) {
        let _ = literal;
        let span_lo = literal.span_lo().to_usize() - 1;
        let span_hi = literal.span_hi().to_usize() - 1;
        let snippet = &self.jscode_raw[span_lo..span_hi];
        if snippet.contains(this_helper::LOCATION_STR) && self.is_literal_or_looks_like_url_or_css(&snippet) {
            self.add_str_to_list(Replacement::new(span_lo, span_hi, snippet.to_string()));
            return;
        }
    }

    fn visit_member_expr(&mut self, member_expr: &MemberExpr) {
        member_expr.visit_children_with(self);
        let span_lo = member_expr.span_lo().to_usize() - 1;
        let span_hi = member_expr.span_hi().to_usize() - 1;
        let snippet = &self.jscode_raw[span_lo..span_hi].to_owned();
        
        if self.contains_skipped_member(span_lo, span_hi) && snippet.contains(this_helper::LOCATION_STR) {
            let object_part_snippet = &self.jscode_raw[member_expr.obj.span_lo().to_usize() - 1..member_expr.obj.span_hi().to_usize() - 1];
            let property_part_snippet = &self.jscode_raw[member_expr.prop.span_lo().to_usize() - 1..member_expr.prop.span_hi().to_usize() - 1];
    
            let type1: bool = object_part_snippet.contains(this_helper::LOCATION_STR);
            let type2: bool = property_part_snippet.contains(this_helper::LOCATION_STR);
            
            if (type1 != type2) && self.can_location_be_replaced_in_member_expression(span_lo, span_hi) {
                for cur_occurrence in find_all_occurrences(snippet, &self.jscode_raw) {
                    let start = cur_occurrence;
                    let end = start + snippet.len() - 1;
                    let mut span_lo_copy = start;
                    let mut span_hi_copy = end + 1;
                    let char_before_first_one = if start > 0 {&self.jscode_raw[start - 1..start]} else {""};
                    let char_after_last_one = if end + 1 < self.jscode_raw.len() {&self.jscode_raw[end + 1..end + 2]} else {""};
                    let mut char_before_is_fine = start == 0 || self.allowed_chars_regexp.is_match(char_before_first_one);
                    let char_after_is_fine = char_after_last_one.is_empty() || self.allowed_chars_regexp.is_match(char_after_last_one);
                    
                    if !char_before_is_fine {
                        let char_first_one = if start > 0 {&self.jscode_raw[start..start + 1]} else {""};
                        if char_first_one == "[" {char_before_is_fine = true;}
                    }

                    if char_before_is_fine && char_after_is_fine {
                        let mut replaced = String::new();
                        if !char_before_first_one.is_empty() {
                            span_lo_copy -= 1;
                            span_hi_copy += 1;
                            replaced.push_str(char_before_first_one);
                            replaced.push_str(&self.jscode_raw[start..end + 1]);
                        } else {
                            span_hi_copy += 1;
                            replaced.push_str(&self.jscode_raw[start..end + 1]);
                        }
        
                        let modified_snippet = &self.jscode_raw[start..end + 1].replace(this_helper::LOCATION_STR, this_helper::MCOP_LOCATION_STR); // Replace with your actual replacements
       
                        let replacement = format!(
                            "{}{}{}",
                            char_before_first_one, modified_snippet, char_after_last_one
                        );
                        self.processed_member_nodes.insert(self.processed_member_nodes.len(), Replacement::new(span_lo_copy, span_hi_copy, replacement.clone()));
                        self.replacements.insert(self.replacements.len(), Replacement::new(span_lo_copy.clone(), span_hi_copy.clone(), replacement.clone()));
                    }
                }
            }
        }
    }

    fn visit_ident(&mut self, ident: &Ident) {
        let span_lo = ident.span_lo().to_usize() - 1;
        let span_hi = ident.span_hi().to_usize() - 1;
        let mut span_lo_copy = span_lo;
        let mut span_hi_copy = span_hi;
        let snippet: &str = &self.jscode_raw[span_lo..span_hi];

        if ident.sym.contains(this_helper::LOCATION_STR) {
            // if span_lo == 347612 {println!("[1] {}", ident.sym);}
            let remaining = snippet.replace(this_helper::LOCATION_STR, "");

            if !remaining.is_empty() {
                self.add_str_to_list(Replacement::new(span_lo, span_hi, snippet.to_string()));
                return;
            }
            
            let char_before = if span_lo > 0 {&self.jscode_raw[span_lo - 1..span_lo]} else {""};
            let char_after = if span_hi < self.jscode_raw.len() {&self.jscode_raw[span_hi..span_hi + 1]} else {""};
        
            let test1 = char_before.is_empty() || self.allowed_chars_regexp.is_match(char_before);
            let test2 = char_after.is_empty() || self.allowed_chars_regexp.is_match(char_after);
        
            if test1 && test2 {
                let original_snippet = format!("{}{}{}", char_before, &self.jscode_raw[span_lo..span_hi], char_after);
                let modified_snippet = original_snippet.replace(this_helper::LOCATION_STR, this_helper::MCOP_LOCATION_STR);
                if !char_before.is_empty() { span_lo_copy -= 1 }
                if !char_after.is_empty() { span_hi_copy += 1 }

                self.replacements.insert(self.replacements.len(), Replacement::new(span_lo_copy.clone(), span_hi_copy.clone(), modified_snippet.clone()));
            }
        }
    }

    fn visit_prop(&mut self, prop: &Prop) {
        prop.visit_children_with(self);
        let span_lo = prop.span_lo().to_usize() - 1;
        let span_hi = prop.span_hi().to_usize() - 1;
        let snippet = &self.jscode_raw[span_lo..span_hi];

        if snippet.contains(this_helper::LOCATION_STR) {
            if let Prop::KeyValue(KeyValueProp { key, .. }) = prop {
                let key_start = key.span_lo().to_usize() - 1;
                let key_end = key.span_hi().to_usize() - 1;
                let key_snippet = &self.jscode_raw[key_start..key_end];
                if key_snippet.contains(this_helper::LOCATION_STR)
                {
                    let new_replaces = &mut self.replace_location_in_property(prop.clone(), &self.jscode_raw.clone(), true);
                    self.replacements.append(new_replaces);
                }
            }
            
            if let Prop::KeyValue(KeyValueProp { value, .. }) = prop {
                let value_start = value.span_lo().to_usize() - 1;
                let value_end = value.span_hi().to_usize() - 1;
                let value_snippet = &self.jscode_raw[value_start..value_end];
                if value_snippet.contains(this_helper::LOCATION_STR)
                {
                    let new_replaces = &mut self.replace_location_in_property(prop.clone(), &self.jscode_raw.clone(), false);
                    self.replacements.append(new_replaces);
                }
            }
        }

    }

    fn visit_object_pat(&mut self, obj_pattern: &ObjectPat) {
        obj_pattern.visit_children_with(self);
        let span_lo = obj_pattern.span_lo().to_usize() - 1;
        let span_hi = obj_pattern.span_hi().to_usize() - 1;
        let snippet = &self.jscode_raw[span_lo..span_hi];
        
        if snippet.contains(this_helper::LOCATION_STR) {
            for cur_prop in obj_pattern.props.clone() {
                let prop_snippet = &self.jscode_raw[cur_prop.span_lo().to_usize() - 1..cur_prop.span_hi().to_usize() - 1];
                if !prop_snippet.contains(this_helper::LOCATION_STR) {
                    continue;
                }
                if let ObjectPatProp::KeyValue(KeyValuePatProp { key, .. }) = cur_prop {
                    if let PropName::Ident(Ident { span: _, sym: key_name, .. }) = key.clone() {
                        if key_name.clone().as_str() == this_helper::LOCATION_STR {
                            self.replacements.insert(self.replacements.len(),
                            Replacement::new(
                                key.span_lo().to_usize() - 1,
                                key.span_hi().to_usize() - 1,
                                this_helper::MCOP_LOCATION_STR.to_string()
                            ));
                        };
                    }
                }
            }
        }
    }

    fn visit_call_expr(&mut self, call_expression: &CallExpr) {
        call_expression.visit_children_with(self);

        let span_lo = call_expression.span_lo().to_usize() - 1;
        let span_hi = call_expression.span_hi().to_usize() - 1;

        if !self.contains_skipped_call(span_lo, span_hi) {
            if let Callee::Expr(callee_expr) = &call_expression.callee {
                let callee_start = callee_expr.span_lo().to_usize() - 1;
                let callee_end = callee_expr.span_hi().to_usize() - 1;
                let callee_snippet = &self.jscode_raw[callee_start..callee_end];
                match callee_snippet.find(this_helper::POST_MESSAGE_NAME) {
                    Some(val) => {
                        let arguments: &Vec<ExprOrSpread> = &call_expression.args;
                        if arguments.len() >= 1 && arguments.len() < 4 {
                            let call_part = this_helper::POST_MESSAGE_NAME;
                            let modified_snippet = format!("{}({})", call_part, self.build_arguments_part(arguments));
                            self.replacements.insert(self.replacements.len(), Replacement::new(
                                span_lo + val,
                                span_hi.clone(),
                                modified_snippet.clone()
                            ));
                            self.processed_callee_nodes.insert(self.processed_callee_nodes.len(), Replacement::new(
                                span_lo + val,
                                span_hi.clone(),
                                modified_snippet.clone()
                            ));
                        }
                    }
                    None => return
                }
            }
        }
    }

    fn visit_tpl_element(&mut self, tpl_elem: &TplElement) {
        let span_lo = tpl_elem.span_lo().to_usize() - 1;
        let span_hi = tpl_elem.span_hi().to_usize() - 1;
        let snippet = &self.jscode_raw[span_lo..span_hi];

        let re = Regex::new(this_helper::LOCATION_STR).unwrap();
        let matches: Vec<(&str, usize, usize)> = re.find_iter(snippet)
            .map(|mat| (mat.as_str(), mat.start(), mat.end())).collect();
        for (_mat, start, end) in matches {
            let char_before_mat = if start > 0 {&snippet[start - 1..start]} else {""};
            let char_after_mat = if end < snippet.len() {&snippet[end..end + 1]} else {""};
            let two_char_after_mat = if end < snippet.len() - 1 {&snippet[end..end + 2]} else {""};

            let re_allowed_chars_regexp = Regex::new(r"[=,;():?\[\]+\-{}&|!<>\s\n\r\.]").expect("Invalid regex pattern");
            let re_allowed_2chars_regexp = Regex::new(r"\.\w").expect("Invalid regex pattern");
    
            let char_before_is_fine = char_before_mat.is_empty()
                || re_allowed_chars_regexp.is_match(&char_before_mat);
            let char_after_is_fine = char_after_mat.is_empty()
                || re_allowed_chars_regexp.is_match(&char_after_mat);
            let two_char_after_is_fine = two_char_after_mat.is_empty()
                || re_allowed_2chars_regexp.is_match(&two_char_after_mat);
                
            let surround_is_fine: bool = (char_before_mat == "." && char_after_is_fine)
                || (char_before_is_fine && two_char_after_is_fine)
                || (char_before_mat == "\'" && char_after_mat == "\'")
                || (char_before_mat == "\"" && char_after_mat == "\"");

            if surround_is_fine {
                self.replacements.insert(self.replacements.len(), Replacement::new(
                    span_lo + start,
                    span_lo + end,
                    this_helper::MCOP_LOCATION_STR.to_string()
                ));
            }
        }
    }

    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call_expr) => {
                self.visit_call_expr(call_expr);
            }
            _ => {
                expr.visit_children_with(self);
            }
        }
    }
}

#[derive(Hash, Eq, PartialEq, Debug)]
struct Replacement {
    start: usize,
    end: usize,
    to: String,
}

impl Replacement {
    fn new(start: usize, end: usize, to: String) -> Self {
        Replacement {
            start,
            end,
            to,
        }
    }

    fn from(rplmnt: &Replacement) -> Self {
        Replacement {
            start: rplmnt.start.clone(),
            end: rplmnt.end.clone(),
            to: rplmnt.to.clone(),
        }
    }
}