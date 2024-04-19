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
      let pass = true;
        pass&=(pw[4] == (pw[1] - 4));
        pass&=(pw[1] == (pw[0] ^ 68));
        pass&=(pw[0] == (pw[2] - 7));
        pass&=(pw[3] == (pw[2] ^ 37));
        pass&=(pw[5] == (pw[0] ^ 20));
        pass&=(pw[4] == (pw[1] - 4));
        pass&=(pw[0] == (pw[3] ^ 34));
        pass&=(pw[0] == (pw[2] - 7));
        pass&=(pw[0] == (pw[5] + 12));
        pass&=(pw[2] == (pw[4] + 71));
        pass&=(pw[2] == (pw[5] ^ 19));
        pass&=(pw[5] == (pw[3] ^ 54));
        pass&=(82 == (pw[3]));

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
