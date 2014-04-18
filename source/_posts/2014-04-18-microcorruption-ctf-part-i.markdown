---
layout: post
title: "Microcorruption CTF - Part I"
date: 2014-04-18 23:29:17 +0300
comments: false
categories: 
---

Introduction
------------
[Microcorruption CTF](https://microcorruption.com) (or uctf) is a security challenge in which you are given an electronic lock (Lockit all LockIT Pro) based on the [TI MSP430](http://en.wikipedia.org/wiki/TI_MSP430) microcontroller and a debugger connected to it. The objective is to find inputs that will unlock the device in order to allow access to your operatives scattered around the world into different warehouses. The device even has his own bogus [manual](https://microcorruption.com/manual.pdf) which is a must read.

In this post I will write and explain my solutions to the various levels of the challenge. Please note that I did not try to optimize my solution - that is, there are solution with shorter input and which use less CPU cycles. In the future I might update this post with more elegant solutions.

First level: New Orleans
------------------------
