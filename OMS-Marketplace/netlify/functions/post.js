const formidable = require('formidable');
const path = require('path');
const { read, write, uuidv4 } = require('./_helpers');
exports.handler = async (event) => {
return new Promise((resolve)=>{
const form = new formidable.IncomingForm({uploadDir:path.join(__dirname,'../public/images'),keepExtensions:true});
form.parse(event, (err, fields, files)=>{
if(err) return resolve({statusCode:500,body:'Error'});
const pending = read('pending.json');
const file = files.image;
const filename = path.basename(file.filepath);
pending.push({id:uuidv4(),user:fields.user,title:fields.title,description:fields.description,price:fields.price,image:filename});
write('pending.json',pending);
resolve({statusCode:200,body:'Item submitted for approval'});
});
});
};
