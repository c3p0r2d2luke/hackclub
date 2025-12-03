const { read, write, uuidv4 } = require('./_helpers');
exports.handler = async (event) => {
const { username,password,name } = JSON.parse(event.body);
let users = read('users.json');
if(users.find(u=>u.username===username)) return {statusCode:200,body:'Username taken'};
users.push({id:uuidv4(),username,password,name});
write('users.json',users);
return {statusCode:200,body:'Signup successful'};
};
