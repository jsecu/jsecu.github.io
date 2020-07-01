---
layout: post
title:  "Lazysysadmin vulnhub walkthrough"
date:   2020-06-30 18:40:20 -0400
categories: CTFs
---

So this is my first boot2root writeup and hopefully it’s written clearly and your able to follow along. Anyway LazySysAdmin is a beginner box  and if you have through enumeration tactics it should be pretty straightforward. Alright let’s get into it.

First we’ll start with a nmap scan to enumerate the open ports running on the machine.

Syntax : nmap -sV -sC -T4 192.168.179.130