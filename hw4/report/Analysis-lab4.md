# CS 528 Lab 4 Report
Luke Jiang (jiang700@purdue.com)

# Setup
Point A	192.168.15.43		22543
Point B	192.168.15.44		22544

compile: `gcc -o simpletun simpletun.c -l crypto`

# Task 1
For this task, I first changed TCP to UDP by changing the `socket` invocation to use `SOCK_DGRAM`. I then removed the `connect` invocation for TCP connection setup. In the `while(1)` loop, I used `sendto` and `recvfrom` instead of `cread` and `cwrite` on network because they cannot work with UDP.

## Question 2.1
Since packets going through VPN tunnel are most likely already controlled by their own flow, VPN should not enforce additional stream of flow in real-time. Therefore, UDP is preferred over TCP for VPNs.

# Task 2
I chose to use the AES algorithm for cryption. To use this algorithm, I need `openssl/evp` and `openssl/hmac` libraries. It turned out that `openssl/evp` is not readily available in the given VM environment. Therefore, I first replaced the `/etc/apt/sources.list` file with the given content and updated `apt-get` to the newest version using `sudo apt-get update`. I then used `sudo apt-get install libssl-dev` to install the libraries onto the VMs. 

For this step, I hardcoded the key and the initialization vector:
```C
// 256-bit key
unsigned char key[32] = "01234567890123456789012345678901";
// 128-bit initialization vector
unsigned char iv[16] = "0123456789012345";
```

I referenced https://wiki.openssl.org/index.phpEVP_Symmetric_Encryption_and_Decryption for the usage of the EVP library. 

* encryption:

```C
unsigned char ciphertext[128];
int ciphertext_len = encrypt(cred, 128, key, iv, ciphertext);
printf("%d\n", ciphertext_len);
```

* decryption:
```C
unsigned char decryptedtext[128];
int decryptedtext_len = decrypt(buffer, 144 /* should not hardcode */, key, iv,
                        decryptedtext);
decryptedtext[decryptedtext_len] = '\0';
```

## Question 2.2
The encryption algorithms are quite complex to implement. Implementing our own versions of these algorithms is error-prone, difficult to test, and unnecessary labor when a library is available.

# Task 3
## Step 1
I followed the guideline's instructions for generating certificates.

## Step 2
I used the traditional key and password approach. In my server VM I have a file `users.txt` that contains a list of tuples of username and password. When a new user enters its credentials on the client's side, the client sends the encrypted credentials to the server. the server decrypts the credentials and searches for a match in the text file and authenticate the user if the credential is found.

* client side terminal:

![](/Users/lukejiang/Documents/School/CS528/lab4/client.png)

* server side terminal:

![](/Users/lukejiang/Documents/School/CS528/lab4/server.png)


## Question 2.3
When connection is broken, the resource allocated to the broken user should be released. Otherwise, if the server has too many clients its resource will be exhausted.
