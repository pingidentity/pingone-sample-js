function toggleSecret(e, el) {
    el.parentNode.previousElementSibling.type = el.checked ? 'text' : 'password';
    el.parentNode.lastElementChild.innerHTML = el.checked ? '<i class=\'fa fa-fw fa-eye-slash\'>'
        : '<i class=\'fa fa-fw fa-eye\'>';
  }

  let password = document.getElementById("password")
      , confirm_password = document.getElementById("confirmPassword");

  function validatePassword() {
    if (password.value !== confirm_password.value) {
      confirm_password.setCustomValidity("Passwords don't match");
    } else {
      confirm_password.setCustomValidity('');
    }
  }

  password.onchange = validatePassword;
  confirm_password.onkeyup = validatePassword;
