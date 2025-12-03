const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const dataPath = file => path.join(__dirname,'../data',file);
const read = file => fs.existsSync(dataPath(file)) ? JSON.parse(fs.readFileSync(dataPath(file))) : [];
const write = (file,data) => fs.writeFileSync(dataPath(file),JSON.stringify(data,null,2));
module.exports = { read, write, uuidv4 };
