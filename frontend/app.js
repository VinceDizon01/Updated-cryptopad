const API = "";
async function api(path, body) {
  const response = await fetch(API + path, {method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : {"Content-Type":"application/json"},
    body: body === undefined ? undefined : JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok || data.ok === false) throw new Error(data.error || "Request failed.");
  return data;
}
function showStatus(message, bad=false) {
  const el=document.getElementById("status"); if(el){el.textContent=message;el.style.color=bad?"#fda4af":"#5eead4";}
}
function showDecryptDialog(message,title="Decrypted message") {
  const dialog=document.getElementById("decrypt-dialog");
  const output=document.getElementById("decrypted-message");
  if(!dialog || !output) return;
  document.getElementById("decrypt-dialog-title").textContent=title;
  output.textContent=message;
  if(!dialog.open) dialog.showModal();
}
async function generateKey(masterKey) {
  const data=await api("/api/session",{master_key:masterKey});
  const status=document.getElementById("key-status");
  if(status) status.innerHTML="<i></i> Active · "+data.key_bits+"-bit ElGamal key";
  const output=document.getElementById("public-key-output");
  if(output) output.value="p = "+data.public_key.p+"\ng = "+data.public_key.g+"\ny = "+data.public_key.y;
  showStatus("New temporary keypair generated.");
}
document.addEventListener("DOMContentLoaded",()=>{
  const decryptDialog=document.getElementById("decrypt-dialog");
  if(decryptDialog) {
    document.getElementById("close-decrypt-dialog").addEventListener("click",()=>decryptDialog.close());
    document.getElementById("decrypt-dialog-done").addEventListener("click",()=>decryptDialog.close());
    decryptDialog.addEventListener("click",e=>{if(e.target===decryptDialog) decryptDialog.close();});
  }
  const start=document.querySelector("#home form.form-stack");
  if(start) {
    start.addEventListener("submit",async e=>{
      e.preventDefault();
      const a=document.getElementById("master-passphrase").value;
      const b=document.getElementById("confirm-passphrase").value;
      if(a!==b){alert("The passphrases do not match.");return;}
      try{await generateKey(a);location.href="workspace.html";}catch(err){alert(err.message);}
    });
  }
  const decryptForm=document.getElementById("decrypt-form");
  if(decryptForm) decryptForm.addEventListener("submit",async e=>{
    e.preventDefault();
    try{const saved=document.getElementById("encrypted-packet").value.trim();
      const result=saved.startsWith("CRYPTOPAD-ENCRYPTED-NOTE-V1")
        ? await api("/api/decrypt-saved",{file_text:saved,master_key:document.getElementById("existing-master-key").value})
        : await api("/api/decrypt",{packet:JSON.parse(saved)});
      showDecryptDialog(result.text);
    }catch(err){showDecryptDialog(err.message,"Could not decrypt");}
  });
  const editor=document.getElementById("note-content");
  const count=document.getElementById("word-count");
  if(editor && count) editor.addEventListener("input",()=>{const t=editor.value.trim();count.textContent=`Words: ${t?t.split(/\s+/).length:0} · Chars: ${editor.value.length}`;});
  if(document.getElementById("generate-key")) {
    api("/api/key").then(data=>{
      document.getElementById("key-status").innerHTML="<i></i> Active · "+data.key_bits+"-bit ElGamal key";
      document.getElementById("public-key-output").value="p = "+data.public_key.p+"\ng = "+data.public_key.g+"\ny = "+data.public_key.y;
    }).catch(()=>{document.getElementById("key-status").innerHTML="<i></i> No key loaded";});
    document.getElementById("generate-key").addEventListener("click",()=>generateKey(document.getElementById("master-key").value).catch(e=>showStatus(e.message,true)));
    document.getElementById("encrypt-button").addEventListener("click",async()=>{
      try{const text=editor.value;if(!text.trim())throw Error("Write a message first.");
        const result=await api("/api/encrypt",{text});
        document.getElementById("packet-output").value=JSON.stringify(result.packet,null,2);
        showStatus("Message encrypted successfully.");
      }catch(e){showStatus(e.message,true);}
    });
    document.getElementById("decrypt-button").addEventListener("click",async()=>{
      try{const saved=document.getElementById("packet-output").value.trim();
        const result=saved.startsWith("CRYPTOPAD-ENCRYPTED-NOTE-V1")
          ? await api("/api/decrypt-saved",{file_text:saved,master_key:document.getElementById("master-key").value})
          : await api("/api/decrypt",{packet:JSON.parse(saved)});
        editor.value=result.text;editor.dispatchEvent(new Event("input"));
        showStatus("Message decrypted and authenticated.");showDecryptDialog(result.text);
      }catch(e){showStatus(e.message,true);showDecryptDialog(e.message,"Could not decrypt");}
    });
    document.getElementById("clear-button").addEventListener("click",()=>{editor.value="";document.getElementById("packet-output").value="";editor.dispatchEvent(new Event("input"));showStatus("Editor cleared.");});
    document.getElementById("copy-packet").addEventListener("click",()=>navigator.clipboard.writeText(document.getElementById("packet-output").value).then(()=>showStatus("Packet copied.")).catch(()=>showStatus("Clipboard unavailable.",true)));
    document.getElementById("copy-key").addEventListener("click",()=>navigator.clipboard.writeText(document.getElementById("public-key-output").value).then(()=>showStatus("Public key copied.")).catch(()=>showStatus("Clipboard unavailable.",true)));
    document.getElementById("save-packet").addEventListener("click",()=>{
      (async()=>{try {
        const packet=JSON.parse(document.getElementById("packet-output").value);
        if(packet.version!==1 || typeof packet.ciphertext!=="string") throw Error("Encrypt a message before saving.");
        const result=await api("/api/export",{packet});
        const blob=new Blob([result.file_text],{type:"text/plain;charset=utf-8"});
        const url=URL.createObjectURL(blob);
        const title=document.getElementById("note-title").value.trim();
        const safeTitle=title.toLowerCase().replace(/[^a-z0-9_-]+/g,"-").replace(/^-+|-+$/g,"").slice(0,60);
        const a=document.createElement("a");a.href=url;a.download=(safeTitle||"cryptopad-encrypted")+".txt";a.click();
        setTimeout(()=>URL.revokeObjectURL(url),1000);
        showStatus("Encrypted note saved as a .txt file.");
      } catch(e) { showStatus(e instanceof SyntaxError?"Encrypt a message before saving.":e.message,true); }})();
    });
    document.getElementById("lock-button").addEventListener("click",async()=>{try{await api("/api/lock",{});}finally{location.href="index.html";}});
  }
});
