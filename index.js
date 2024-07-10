const jsreplacer = require('.');
const fs = require('fs');

let origin = jsreplacer.read_file_to_string("test-input1.txt");
let modify = jsreplacer.replace_js_code(origin);

fs.writeFile('output.txt', modify, (e) => {console.log(e)});