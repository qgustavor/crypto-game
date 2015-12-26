var fs = require('fs');
var nacl = require('tweetnacl');
nacl.auth = require('tweetnacl-auth');

var challengeData = require('./challenge-data.json');
var resultCode = '';

console.log('Generating challenge based on challenge-data.json');

challengeData.slice().reverse().forEach(function(challenge, index) {
  var loops = challenge.rounds || 20000;
  var password, result;
  
  index = challengeData.length - index - 1;
  
  if (index === 0) {
    resultCode = '<script type="text/challenge" id="level1">' + JSON.stringify(challenge) + '</script>\n' + resultCode;
    rewriteHTMLFile(resultCode);
    return;
  }
  
  password = challengeData[index - 1].answer;
  if (challenge.type === 'text') {
    password = password.trim().toLowerCase(); // normalize
  }
  password = nacl.hash(nacl.util.decodeUTF8(password));
  
  result = nacl.randomBytes(8); // random salt
  challengeData[index - 1].salt = nacl.util.encodeBase64(result);
  
  for (var i = 0; i < loops; i++) {
    result = nacl.auth(result, password.subarray(0, 32));
  }
  
  challengeData[index - 1].answer = nacl.util.encodeBase64(nacl.hash(result));
  
  var message = nacl.util.decodeUTF8(JSON.stringify(challenge));
  var nonce = nacl.randomBytes(24);
  var ciphertext = nacl.secretbox(
    message, nonce, result.subarray(0, 32)
  );
  
  var encoded = new Uint8Array(24 + ciphertext.length);
  encoded.set(nonce); encoded.set(ciphertext, 24);
  
  resultCode = '<script type="text/challenge" id="' + challengeData[index - 1].nextLevel + '">' +
    nacl.util.encodeBase64(encoded) + '</script>\n' + resultCode;
});

function rewriteHTMLFile(resultCode) {
  fs.readFile('../index.html', 'utf-8', function (err, data) {
    if (err) {
      console.log('Could not update HTML file. Does the file got renamed or removed?');
      throw err;
    }
    
    var newData = data.replace(/<!-- game data start -->(?:[\s\S](?!<!-- game data end -->))*[\s\S]<!-- game data end -->/m,
    '<!-- game data start -->\n' + resultCode + '<!-- game data end -->');
    
    if (newData === data) {
      console.log('Could not update HTML file. Placeholder comments got erased?');
      return;
    }
    
    fs.writeFile('../index.html', newData, 'utf-8', function (err) {
      if (err) {
        console.log('Could not update HTML file. Write failed.');
        throw err;
      }
      
      console.log('HTML file updated.');
    });
  });
}