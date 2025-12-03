async function loadItems(){
const res = await fetch('/.netlify/functions/getItems');
const items = await res.json();
const container = document.getElementById('marketplace');
container.innerHTML = '';
items.forEach(i=>{
const div = document.createElement('div');
div.className='item';
div.innerHTML = `<h2>${i.title}</h2><img src="images/${i.image}"/><p>${i.description}</p><p>Price: $${i.price}</p><button>Add to Cart</button>`;
container.appendChild(div);
});
}
loadItems();
