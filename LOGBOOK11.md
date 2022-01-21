# Week 11 Logbook

#### Preparation Steps

- Add the following lines to the `/etc/hosts` file:
    ```
    10.9.0.80 www.bank32.com
    10.9.0.80 www.smith2020.com
    ```

## Task 1

- Copy OpenSSL configuration file to the current directory: `cp /usr/lib/ssl/openssl.cnf .`
- Uncomment `unique_subject` line in the configuration file to allow creation of certifications with the same subject.
- Create necessary subdirectories and files
    ```
    mkdir demoCA demoCA/certs demoCA/crl demoCA/newcerts
    touch demoCA/index.txt
    echo -n 1000 > demoCA/serial
    ```
- Generate self-signed certificate.
    ```bash
    [01/18/22]seed@VM:~/.../Labsetup$ openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -keyout ca.key -out ca.crt
    Generating a RSA private key
    ............................++++
    .............++++
    writing new private key to 'ca.key'
    Enter PEM pass phrase:
    Verifying - Enter PEM pass phrase:
    -----
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) [AU]:PT
    State or Province Name (full name) [Some-State]:Porto
    Locality Name (eg, city) []:Porto
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:FEUP
    Organizational Unit Name (eg, section) []:DEI
    Common Name (e.g. server FQDN or YOUR name) []:FSI
    Email Address []:
    [01/18/22]seed@VM:~/.../Labsetup$ 
    ```
- Examine the decoded content of the X509 certificate and RSA key with the following commands:
    ```
    openssl x509 -in ca.crt -text -noout
    openssl rsa -in ca.key -text -noout
    ```

    ```bash
    [01/18/22]seed@VM:~/.../Labsetup$ openssl x509 -in ca.crt -text -noout
    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number:
                47:d9:6c:40:86:58:c0:92:d0:62:07:19:aa:16:7d:71:2d:e1:b5:e7
            Signature Algorithm: sha256WithRSAEncryption
            Issuer: C = PT, ST = Porto, L = Porto, O = FEUP, OU = DEI, CN = FSI
            Validity
                Not Before: Jan 18 16:48:50 2022 GMT
                Not After : Jan 16 16:48:50 2032 GMT
            Subject: C = PT, ST = Porto, L = Porto, O = FEUP, OU = DEI, CN = FSI
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption
                    RSA Public-Key: (4096 bit)
                    Modulus:
                        00:a8:33:a3...
                    Exponent: 65537 (0x10001)
            X509v3 extensions:
                X509v3 Subject Key Identifier: 
                    B9:30:57:2A:50:59:97:DA:A8:62:11:4B:76:E1:25:F8:B2:1B:9F:7E
                X509v3 Authority Key Identifier: 
                    keyid:B9:30:57:2A:50:59:97:DA:A8:62:11:4B:76:E1:25:F8:B2:1B:9F:7E

                X509v3 Basic Constraints: critical
                    CA:TRUE
        Signature Algorithm: sha256WithRSAEncryption
             48:e9:aa:92...
    [01/18/22]seed@VM:~/.../Labsetup$ openssl rsa -in ca.key -text -noout
    Enter pass phrase for ca.key:
    RSA Private-Key: (4096 bit, 2 primes)
    modulus:
        00:a8:33:a3...
    publicExponent: 65537 (0x10001)
    privateExponent:
        4b:14:09:ad...
    prime1:
        00:cf:b9:df...
    prime2:
        00:cf:4a:5d...
    exponent1:
        6a:f9:57:f4...
    exponent2:
        32:2b:b7:8e...
    coefficient:
        3a:7a:ec:54...
    [01/18/22]seed@VM:~/.../Labsetup$ 
    ```

### Questions

- What part of the certificate indicates this is a CA’s certificate?
    - `CA:TRUE` is present in the X509 extensions.
- What part of the certificate indicates this is a self-signed certificate?
    - The Subject is the same as the Issuer.
- In the RSA algorithm, we have a public exponent e, a private exponent d, a modulus n, and two secret numbers p and q, such that n = pq. Please identify the values for these elements in your certificate and key files.
    - **e** (`publicExponent`): 65537 
    - **d** (`privateExponent`):
            306292629711676810109172647045767014875810428938280739629574425863920279483931237023832694740058495540833440890102947123308211076048028117641588943111986751138909361431848875930664689151552798882726567011028767112734326489454735109235529922381815588981046934568650437738741437716687430780125221188519318306875979299468023600064457579755099910986728926008011965146655193976047803992610405627534172664836103029135065693918031852415640843372570793317276392498896642833729025713679962800581185711790590855646278849562446363679125276275785685333631488647553500851225198236023692598791427914371927866493591399529953922839932334851137959930757519095288637854280038078649803612240717677832452652352764170927781391829878751265419743224901854218776501912744049463731046016424747836398193191999941116244347372744729220577100815809695377458948311989639043848416217005708000307959390826898850642473987529556525508842252409194457831724875104135549693873248392368661187871016087333735723670368388701127904864897881310139296108182548579746360022554484963001003735111219058138947691312243767134037865941813573327817125541766938863947545664290833074392975542759163659156147205209551723487478499898965968974773003205992609890281422528361768052438331701
    - **n** (`modulus`):
        686203126975495269002319343979709187225788400551331652586176431403402842667022236380231884428236885866735077278045904543816026708062749760567354273569557847379438102764129483535636404229491531821599529012470252974644294777950807604483947783924282919873205242225605706699617051366989510513009490343964398997632073816334593466564945694609441180950235997121221076806356320637481452509612968024192632343190909794565507824233618894190813043178756779873323862003903506696547333887035303116319323419602090483249245443673265898760429126287429202465053391839972439930494165275161000302430308386291766197873397584897090563058906027507786475735411110991343798931169599703940684959058215877259085842380636985378244945882385017219679765080017446219635856664847270159380248641818577680610837147369884042595035448204688740170545894932818680652331886690005077974171990972355610725418035164619057038137137171419271736926237857137606752597764428732363763604416537282314057244445420342199064654216544049369537599431025191888207335982434089301541019943192670593411745551903631123405107110917701663485222000892398293186176152183983908522883465401680959393727121217196247876334923484697149751929501145855223989839027443658314550597368980126001537135537521
    - **p** (`prime1`):
        26222987223769058920221255741889485869426934089707307382991028496649206004435436202826344329812509994097875318971960415179389907330014663583282058216790639165589904391180651363998651340728397292623958592547724931091726528398489483841519412664353423113428090721846900981059598473780595768581956837622364309331639900837101804688447668258403941281840519451830343123037360931715097621770245807537093240953717034582290458030503718363251437463159764268832367743371548339975650537284655983994897562664270400580013016110067742350221470126495620069978730562185240513276329347618765935495884084852119036374877271927630513403607
    - **q** (`prime2`):
        26167999897185875818974754303189346303459422144001295902486515869897427500424518782159480219554911707795211070641328284340389573792277896762967924372692625350201017835978168679305563569210439313793260111507890308219426463696151383242186122194753826328310741128947922825317626117951665787789693709987365153946079785223024997653776187571249327407885856622798452038603249275360493440456962195289288926155917652485109748612718264759573730754578860855249018273644145725370774221515196524269360771804295199174193826505934331018709277466336192393909721201887486875888855117911561725351164019581654226239095119988757999738103

## Task 2

- Generate the CSR for `www.bank32.com` with two alternative names.
    ```
    openssl req -newkey rsa:2048 -sha256 \
    -keyout server.key -out server.csr \
    -subj "/CN=www.bank32.com/O=Bank32 Inc./C=US" \
    -passout pass:dees \
    -addext "subjectAltName = DNS:www.bank32.com, \
        DNS:www.bank32.biz, \
        DNS:www.bank32.xyz"
    ```

## Task 3

- Uncomment the `copy_extensions = copy` line in the configuration file to allow the `openssl ca` command to copy the extension field to the certificate.
- Turn the CSR into an X509 certificate (using our custom OpenSSL configuration file):
    ```
    [01/18/22]seed@VM:~/.../Labsetup$ openssl ca -config myCA_openssl.cnf -policy policy_anything \
    > -md sha256 -days 3650 \
    > -in server.csr -out server.crt -batch \
    > -cert ca.crt -keyfile ca.key
    Using configuration from myCA_openssl.cnf
    Enter pass phrase for ca.key:
    Check that the request matches the signature
    Signature ok
    Certificate Details:
            Serial Number: 4097 (0x1001)
            Validity
                Not Before: Jan 18 17:38:28 2022 GMT
                Not After : Jan 16 17:38:28 2032 GMT
            Subject:
                countryName               = US
                organizationName          = Bank32 Inc.
                commonName                = www.bank32.com
            X509v3 extensions:
                X509v3 Basic Constraints: 
                    CA:FALSE
                Netscape Comment: 
                    OpenSSL Generated Certificate
                X509v3 Subject Key Identifier: 
                    27:D3:9F:E9:EE:30:A3:44:E4:D7:B5:C4:FC:52:45:31:51:01:51:8B
                X509v3 Authority Key Identifier: 
                    keyid:B9:30:57:2A:50:59:97:DA:A8:62:11:4B:76:E1:25:F8:B2:1B:9F:7E

                X509v3 Subject Alternative Name: 
                    DNS:www.bank32.com, DNS:www.bank32.biz, DNS:www.bank32.xyz
    Certificate is to be certified until Jan 16 17:38:28 2032 GMT (3650 days)

    Write out database with 1 new entries
    Data Base Updated
    ```
- he alternative names are present in the certificate extensions (see `X509v3 Subject Alternative Name`):
    ```
    [01/18/22]seed@VM:~/.../Labsetup$ openssl x509 -in server.crt -text -nooutCertificate:    Data:
            Version: 3 (0x2)
            Serial Number: 4097 (0x1001)
            Signature Algorithm: sha256WithRSAEncryption
            Issuer: C = PT, ST = Porto, L = Porto, O = FEUP, OU = DEI, CN = FSI
            Validity
                Not Before: Jan 18 17:38:28 2022 GMT
                Not After : Jan 16 17:38:28 2032 GMT
            Subject: C = US, O = Bank32 Inc., CN = www.bank32.com
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption
                    RSA Public-Key: (2048 bit)
                    Modulus:
                        00:be:58:b2...
                    Exponent: 65537 (0x10001)
            X509v3 extensions:
                X509v3 Basic Constraints: 
                    CA:FALSE
                Netscape Comment: 
                    OpenSSL Generated Certificate
                X509v3 Subject Key Identifier: 
                    27:D3:9F:E9:EE:30:A3:44:E4:D7:B5:C4:FC:52:45:31:51:01:51:8B
                X509v3 Authority Key Identifier: 
                    keyid:B9:30:57:2A:50:59:97:DA:A8:62:11:4B:76:E1:25:F8:B2:1B:9F:7E

                X509v3 Subject Alternative Name: 
                    DNS:www.bank32.com, DNS:www.bank32.biz, DNS:www.bank32.xyz
        Signature Algorithm: sha256WithRSAEncryption
             1c:a6:37:8c...
    [01/18/22]seed@VM:~/.../Labsetup$ 
    ```

## Task 4

- Set up the website
    - Copy the `server.crt`, `server.key` files that we generated to the `image_www/certs` folder.
    - Change the `Dockerfile` in order to copy these files to the container and set the proper permissions:
    ```dockerfile
    FROM handsonsecurity/seed-server:apache-php

    ARG WWWDIR=/var/www/bank32

    COPY ./index.html ./index_red.html $WWWDIR/
    COPY ./bank32_apache_ssl.conf /etc/apache2/sites-available
    COPY ./certs/server.crt ./certs/server.key  /certs/

    RUN  chmod 400 /certs/server.key \
         && chmod 644 $WWWDIR/index.html \
         && chmod 644 $WWWDIR/index_red.html \
         && a2ensite bank32_apache_ssl   

    CMD  tail -f /dev/null
    ```
    - Modify the `bank32_apache_ssl.conf` file (`ServerAlias`, `SSLCertificateFile` and `SSLCertificateKeyFile` were changed):
    ```conf
    <VirtualHost *:443> 
        DocumentRoot /var/www/bank32
        ServerName www.bank32.com
        ServerAlias www.bank32.biz
        ServerAlias www.bank32.xyz
        DirectoryIndex index.html
        SSLEngine On 
        SSLCertificateFile /certs/server.crt
        SSLCertificateKeyFile /certs/server.key
    </VirtualHost>

    <VirtualHost *:80> 
        DocumentRoot /var/www/bank32
        ServerName www.bank32.com
        DirectoryIndex index_red.html
    </VirtualHost>
    
    # Set the following global entry to suppress an annoying warning message
    ServerName localhost
   ```
- Get a shell in the Docker container and start Apache:
    ```
    root@d4cdf490d084:/# service apache2 start
     * Starting Apache httpd web server apache2 
     Enter passphrase for SSL/TLS keys for www.bank32.com:443 (RSA):
     * 
    root@d4cdf490d084:/#
    ```

When using HTTP (<http://www.bank32.com>) the site can be accessed:

![](https://i.imgur.com/RY3u247.png)

Trying to access <https://www.bank32.com> using Firefox yielded the following warning:

> Warning: Potential Security Risk Ahead
> 
> Firefox detected a potential security threat and did not continue to www.bank32.com. If you visit this site, attackers could try to steal information like your passwords, emails, or credit card details.
> 
> What can you do about it?
> 
> The issue is most likely with the website, and there is nothing you can do to resolve it.
> 
> If you are on a corporate network or using anti-virus software, you can reach out to the support teams for assistance. You can also notify the website’s administrator about the problem.

The details are:

> Someone could be trying to impersonate the site and you should not continue.
>  
> Websites prove their identity via certificates. Firefox does not trust www.bank32.com because its certificate issuer is unknown, the certificate is self-signed, or the server is not sending the correct intermediate certificates.
>  
> Error code: SEC_ERROR_UNKNOWN_ISSUER

When clicking *View Certificate*, we can check that the certificate we generated is being used:

![](https://i.imgur.com/IQKk1rf.png)

Essentially, Firefox did not connect to the website because it doesn't know the issuer of the website's certificate and therefore cannot trust it (error code `SEC_ERROR_UNKNOWN_ISSUER`). To fix the problem, we need to add the self-signed certificate of our CA to Firefox's list of trusted CAs.

![](https://i.imgur.com/zJsYk64.png)

![](https://i.imgur.com/w1KuEGR.png)

After refreshing the page, we can now browse the HTTPS website:

![](https://i.imgur.com/Nku3r1D.png)

## Task 5

To simulate a Man in the Middle attack, we chose www.github.com as the target website.
- We simulated DNS cache poisoning in the user's machine by modifying the `/etc/hosts` file to contain the following line:
    ```
    10.9.0.80  www.github.com
    ```
- Now requests for www.github.com will be redirected to our malicious server.

When attempting to browse www.github.com, Firefox displays a certificate warning with the following details:

> Websites prove their identity via certificates. Firefox does not trust this site because it uses a certificate that is not valid for www.github.com. The certificate is only valid for the following names: www.bank32.com, www.bank32.biz, www.bank32.xyz
> 
> Error code: SSL_ERROR_BAD_CERT_DOMAIN
 
This is because the certificate we're using, signed by our CA, does not have www.github.com as an alternative name, and as such the browser does not accept the certificate to access this website.

## Task 6

When the root CA is compromised, the `ca.key` file can be used to generate any certificate the attacker wants to.

1. Generate the CSR for our malicious `www.github.com` website:
    ```
    openssl req -newkey rsa:2048 -sha256 \
    -keyout server.key -out server.csr \
    -subj "/CN=www.github.com/O=Bank32 Inc./C=US" \
    -passout pass:dees \
    -addext "subjectAltName = DNS:www.github.com, \
        DNS:www.bank32.com, \
        DNS:www.bank32.biz, \
        DNS:www.bank32.xyz"
    ```

2. Sign the certificate with the CA private key, turning the CSR into a X509 certificate.

    ```
    openssl ca -config myCA_openssl.cnf -policy policy_anything \
        -md sha256 -days 3650 \
        -in server.csr -out server.crt -batch \
        -cert ca.crt -keyfile ca.key
    ```

3. Copy the `server.crt`, `server.key` files that we generated to the image_www/certs folder, replacing the certificate used in the previous task.

4. Restart the container and start apache.
5. The malicious website is now being shown without any browser suspicion.

The following certificate is being used by the browser to access `www.github.com`:

![](https://i.imgur.com/KiZlji6.png)

