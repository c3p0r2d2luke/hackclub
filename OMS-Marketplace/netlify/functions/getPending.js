const { read } = require('./_helpers');
exports.handler = async () => {
const pending = read('pending.json');
return {statusCode:200,body:JSON.stringify(pending)};
};
