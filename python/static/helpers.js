/**
 * Get Access Token from the current page URL
 */
function checkAccessTokenFromUrl() {
    let url = window.location.href;
      if (url.match('[?#&]access_token=([^&]*)')) {
        let xhr = new XMLHttpRequest();
        xhr.open("POST", "/callback", true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onreadystatechange = function() {
            if(xhr.readyState === XMLHttpRequest.DONE && xhr.status == 200) {
                // Clear the hash and reload the page
                 window.location.hash = '';
                 window.location.reload();
            }
        }
        xhr.send("responseUrl=" + window.location.href);
      }
}
/**
 * Get error from the current page URL
 */
function checkErrorFromUrl() {
    let url = window.location.href;
      let error_description = url.match('[?&#]error_description=([^&]*)');
      if (error_description) {
        let newNode = document.createElement('div');
        newNode.className = "alert alert-danger";
        newNode.innerHTML = decodeURI(error_description[1]);
        let referenceNode = document.getElementById('title');
        referenceNode.parentNode.insertBefore(newNode, referenceNode.nextSibling);
      }
}

checkAccessTokenFromUrl();
checkErrorFromUrl();
