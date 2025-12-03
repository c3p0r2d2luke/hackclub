const { read, write } = require('./_helpers');
require('dotenv').config();
exports.handler = async (event) => {
const { itemId,password } = JSON.parse(event.body);
if(password!==process.env.ADMIN_PASSWORD) return {statusCode:403,body:'Unauthorized'};
let pending = read('pending.json');
pending = pending.filter(i=>i.id!==itemId);
write('pending.json',pending);
return {statusCode:200,body:'Rejected'};
};
