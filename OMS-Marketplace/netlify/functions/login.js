const { read } = require('./_helpers');
exports.handler = async (event) => {
const { username,password } = JSON.parse(event.body);
const users = read('users.json');
const user = users.find(u=>u.username===username && u.password===password);
if(user) return {statusCode:200,body:JSON.stringify({userId:user.id})};
else return {statusCode:200,body:JSON.stringify({error:'Invalid login'})};
};
