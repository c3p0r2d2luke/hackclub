const { read } = require('./_helpers');
exports.handler = async () => {
const items = read('items.json');
return {statusCode:200,body:JSON.stringify(items)};
};
