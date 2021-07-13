---
layout: post
title:  "Pentesting Workshop: Working with OWASP JuiceShop"
image: /images/pentester.png
date:   2020-07-3 14:05
categories: header
---

This is a simple introduction of OWASP Juiceshop that I presented at day 2 of my pentesting workshop. It covers 5 of the OWASP top 10 and gives examples of where you can find them in the JuiceShop platform. This is meant to be a practical follow along guide with the JuiceShop platform so if you use this guide to learn web application pentesting, it would be advised to download JuiceShop beforehand.

<center><img src="../../../../images/pentester.png"></center>

In this Workshop we’re going to be looking more depth at web applications. Last workshop we covered more of the bigger picture when we looked at ports and IP addresses. Web Applications usually reside on port 80 on application servers. Popular application servers include Apache, IIS and Nginx. In a lot of cases web application vulnerabilities can be a great way for hackers to infiltrate into a server and gain a foothold on an network. In order to learn about web application pentesting we’re going to use an intentionally vulnerable web application created by OWASP called JuiceShop. Juice Shop is based off a modern web application that includes many of the same functions you would see in a real production website. OWASP is a group that promotes good security practices and even makes a top 10 most abused web applications list every year:

<center><img src="../../../../images/owasp.jpeg.webp"></center>

In today’s workshop we’re only going to cover 4 out of the 10 categories listed in their Top 10. These categories include 

    Injection
    Broken Authentication
    Cross Site Scripting
    Broken Access Control

In order to launch the Juice Shop program, just go to the url I provide during the Workshop. If you want to access it at home it’s easy to setup using heroku.com, you can access instructions for this at this url: <a href="https://github.com/bkimminich/juice-shop">https://github.com/bkimminich/juice-shop</a>

Tools Needed:

    FireFox 

Firefox has  good tools for intercepting background web traffic including http requests, responses and api calls. 

<h1>i.Injection</h1>

“Injection flaws allow attackers to relay malicious code through an application to another system. These attacks include calls to the operating system via system calls, the use of external programs via shell commands, as well as calls to backend databases via SQL (i.e., SQL injection). Whole scripts written in Perl, Python, and other languages can be injected into poorly designed applications and executed. Any time an application uses an interpreter of any type there is a danger of introducing an injection vulnerability.

SQL injection is a particularly widespread and dangerous form of injection. To exploit a SQL injection flaw, the attacker must find a parameter that the web application passes through to a database. By carefully embedding malicious SQL commands into the content of the parameter, the attacker can trick the web application into forwarding a malicious query to the database. These attacks are not difficult to attempt and more tools are emerging that scan for these flaws. The consequences are particularly damaging, as an attacker can obtain, corrupt, or destroy database contents.

Injection vulnerabilities can be very easy to discover and exploit, but they can also be extremely obscure. The consequences of a successful injection attack can also run the entire range of severity, from trivial to complete system compromise or destruction. In any case, the use of external calls is quite widespread, so the likelihood of an application having an injection flaw should be considered high” -OWASP <a href="https://github.com/bkimminich/juice-shop">https://github.com/bkimminich/juice-shop</a>

To illustrate this vulnerability we’re going to exploit a sql injection in the login portal of the Juice Shop application. This technique is used to bypass login screens and get access to privileged users. So imagine the SQL query to the database  from a login page is “ SELECT username, password from Users where username = “[username here]” and password = “[password here]” “. We have access to this query when we input data in a login form, which means we can control it using our own SQL queries. What we can do here is enter ‘ or 1=1 — in the username field and anything for the password field. So the query would now look like “SELECT username, password from Users where username=’’or 1=1 — and password = aaa”. What the ‘or 1=1 — does is closes the previous quote with a quote and makes a second condition with the or command. The 1=1 is stating to return if true, since 1=1 is always true, we’ll be supplied with the first user in the database. The — at the end comments out the rest of SQL query. After that executes we’re now logged in as a admin user. 

<h3>Mitigation:</h3>

Usually this happens because the SQL interpreter can’t differentiate between the query and application data. There are several ways to block this type of attack from happening, but the most successful way is using prepared statements. This allows for a static sql query instead of an dynamic one that was used before and you can pass external input into this static query through parameters.The query is already precompiled so it doesn’t have to execute again after replacing user data from the parameters so if there is SQL in the input it won’t be compiled. The static query from our example below would like: “ SELECT username, password from Users where username = “?” and password = “?” ” The question marks representing  the parameters. 


<h1>ii.Broken Auth</h1>

“These types of weaknesses can allow an attacker to either capture or bypass the authentication methods that are used by a web application.

 

    User authentication credentials are not protected when stored.
    Predictable login credentials.
    Session IDs are exposed in the URL (e.g., URL rewriting).
    Session IDs are vulnerable to session fixation attacks.
    Session value does not timeout or does not get invalidated after logout.
    Session IDs are not rotated after successful login.
    Passwords, session IDs, and other credentials are sent over unencrypted connections.

The goal of an attack is to take over one or more accounts and for the attacker to get the same privileges as the attacked user.”-OWASP

To illustrate this type of attack, we’re going to abuse a compromised security question answer in the forgot password function of the application. When a attacker is targeting a site or person diligently any information on the internet can be leveraged to gain access to their accounts. In this example the creator of the application made a presentation on youtube for an conference explaining the Juice Shop application. In the video he makes his account live and writes his security question answer in plaintext. Using this security question answer we can reset his account with the forgot password function. This is the url for link to the conference talk:<a href="https://www.youtube.com/watch?v=Lu0-kDdtVf4">https://www.youtube.com/watch?v=Lu0-kDdtVf4</a>

<h3>Mitigation:</h3>

In this case there’s two issues, a compromised security question and a weak forget password function. User lack of awareness to security can also be an vulnerability in a corporation, and employee security training is an essential step in improving that issue. The forgot password function should use a stronger form of proof of identity, possibly a email sent with reset instructions, a verification code made from a  device that’s connected with the user on the application. Not just a security question that’s easily guessable with a little recon of the target. Keep in mind a lot of people’s security question answers are on their social media in plain sight.

<h1>iii.Cross Site Scripting</h1>

Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application uses input from a user within the output it generates without validating or encoding it.-OWASP

For Cross Site Scripting, it’s injecting javascript into a application. You can leverage this vulnerability to steal cookies, bypass other protections to chain with other vulnerabilities and could potentially lead to a full browser compromise. For this example we’re just going to display a alert box using javascript code. A good way to identify vulnerable components is seeing if user input is reflected back to the screen somehow. There are different types of XSS but in this case we’re going to be exploiting a DOM XSS. A DOM XSS means that our input is reflected into the DOM of the webpage, through client side javascript.An DOM XSS consists of a source and a sink.A source is javascript function that takes user controllable input such as the url fragments,the referrer header, or even cookie names.A sink is a javascript function that takes user input from the source and displays it in the DOM without default sanitization. In to order to exploit this we have to login and go to track orders. We can use FireFox’s dev tools to look at what happens in the backend. After this we can run this query `<img src =x onerror= alert(1)>` instead of random letters.This syntax works for two reasons. The first reason is that script tags aren't allowed to be executed in innerHTML, the sink in this case(unless you use srcdoc with an iframe),so a img tag will replace the usually used script tag and work just fine in this scenario.The second reason is that this tells the application to look for the img source of x, but since that doesn’t exist it runs our actual javascript on error,which pops up a alert box with a 1 in it.

<h3>Mitigation:</h3>

Proper validation of any user input is key in stopping cross site scripting. Encoding any special characters with htmlentities() or any other related function while encoding any type of input in a web application is a good fix. 

 
<h1>iv.Broken Access Control</h1>

 
Access control, sometimes called authorization, is how a web application grants access to content and functions to some users and not others. These checks are performed after authentication, and govern what ‘authorized’ users are allowed to do. Access control sounds like a simple problem but is insidiously difficult to implement correctly. A web application’s access control model is closely tied to the content and functions that the site provides. In addition, the users may fall into a number of groups or roles with different abilities or privileges.-OWASP

For this example, we’re going to be accessing  another’s users basket. In order to do this we have to make two user accounts. For the first one we’re going to add a number of items to the basket. In the second account we’re going to use Firefox dev tools to change the BID stored in the session we’re given after logging in. After we click the Storage tab we should see a section called Session Storage. In  that section there’s a value called bid. We’re going to change that bid to the other bid of the account we added items too. After this you should be able to see the other accounts basket with all the items included in the cart. Imagine the risk if this was a actual scenario and someone had their credit card tied to the account and an attacker clicked checkout and changed the delivery information to his own. 

 
<h3>Mitigation:</h3>

In this scenario the proper mitigation would be not to have the bid stored locally but on the server, and to provide encryption and checks to make sure that value wasn’t tampered with during the sending of the request. The main problem is that’s their no access controls to check if the bid is used for the correct user. 


