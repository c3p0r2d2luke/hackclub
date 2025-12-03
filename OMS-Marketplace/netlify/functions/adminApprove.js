const { read, write } = require('./_helpers');
require('dotenv').config();
exports.handler = async (event) => {
const { itemId,password } = JSON.parse(event.body);
if(password!==process.env.ADMIN_PASSWORD) return {statusCode:403,body:'Unauthorized'};
let pending = read('pending.json');
let items = read('items.json');
const index = pending.findIndex(i=>i.id===itemId);
if(index!==-1){ items.push(pending[index]); pending.splice(index,1); write('items.json',items); write('pending.json',pending); }
return {statusCode:200,body:'Approved'};
};
