let password = "";

function addToPassword(num) {
  if (password.length < 6) {
    password += num;
    updateDisplay();
    if (password.length === 6) {
      let pw = Array(6);
      for(let i = 0; i < 6; i+=1) {
        pw[i] = password[i].charCodeAt(0);
      }
      //<constraints>//
      if(pass){
        document.getElementById("display").classList.add("correct");
        let flag = "U2FsdGVkX19WKWdho02xWkalqVZ3YrA7QrNN4JPOIb5OEO0CW3Qj8trHrcQNOwsw"
        let decrypted_flag = CryptoJS.AES.decrypt(flag, password).toString(CryptoJS.enc.Utf8);
        console.log(decrypted_flag);
        document.getElementById("display").textContent = decrypted_flag;
      }
      else{
        document.getElementById("display").classList.add("wrong");
      }
    }
  }
}

function clearPassword() {
  password = ""
  updateDisplay();
  document.getElementById("display").classList.remove("correct");
  document.getElementById("display").classList.remove("wrong");
}

function deletePassword() {
  password = password.slice(0, -1);
  updateDisplay();
}

function updateDisplay() {
  document.getElementById("display").textContent = "*".repeat(password.length);
}
