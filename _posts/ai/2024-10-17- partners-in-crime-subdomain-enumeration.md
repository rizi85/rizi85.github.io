---
title: "Partners in Crime #1 Reconnaissance: Subdomain Enumeration"
classes: wide
header:  
  teaser: /assets/images/posts/ai/partners.jpg
  #overlay_image: /assets/images/main/header3.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Welcome to \"Partners in Crime\" a series that dives into the intriguing world of using AI for offensive security. We’re here to explore how artificial intelligence can become your trusty accomplice in penetration testing—turning the tedious and challenging parts of pentesting into a walk in the park. We'll focus on real, practical methods of leveraging AI, aiming to supercharge your skills as a pentester and make your engagements more effective (and maybe even more fun)."
description: "Partners in Crime: Using AI for Offensive Security"
categories:
  - AI
tags:
  - subdomain
  - enumeration
  - AI
  - prompting
  - reconnaissance
toc: false
---

<img src="/assets/images/posts/ai/partners.jpg" alt="Partners in Crime" width="500" class="align-center">

Welcome to "Partners in Crime" a series that dives into the intriguing world of using AI for offensive security. We’re here to explore how artificial intelligence can become your trusty accomplice in penetration testing turning the tedious and challenging parts of pentesting into a walk in the park. We'll focus on real, practical methods of leveraging AI, aiming to supercharge your skills as a pentester and make your engagements more effective (and maybe even more fun).

Today, we’re talking about subdomain enumeration one of the foundational tasks in the reconnaissance phase of penetration testing. And what better way to do it than with a little help from AI? Let’s see how AI can save you time, expand your reach, and uncover those elusive subdomains in a real pentesting engagement.

**AI for Subdomain Enumeration: Finding Hidden Gems**

Subdomain enumeration is an important part of the reconnaissance process. By finding subdomains, pentesters can get a broader view of the target surface and identify services that may hold potential vulnerabilities. Imagine you're tasked with pentesting a domain called `abcxyz.com`. It sounds simple enough, but as every pentester knows, finding all the nooks and crannies (i.e., subdomains) can be a painstaking process. This is where AI can be your sidekick, helping you uncover all those hidden gems.

Let’s explore a few ways you can use AI to enumerate subdomains in a real engagement scenario:

### 1. Using GPT-4 for Creative Subdomain Guessing

Sometimes, traditional tools like `Sublist3r` or `Amass` may not catch every subdomain. AI language models like GPT-4 can be surprisingly effective at guessing unconventional subdomains that automated tools might miss. For example, you could prompt GPT-4 with:

*“Generate potential subdomains for **`abcxyz.com`**, including both common and creative names, taking into consideration services like mail, dev environments, staging, or any marketing campaigns.”*

The AI will output a list that includes standard options (`mail.abcxyz.com`, `dev.abcxyz.com`, `staging.abcxyz.com`) and also some more creative ones (`beta.abcxyz.com`, `promo.abcxyz.com`, `test1.abcxyz.com`). This helps uncover areas often missed by purely automated scans, especially when companies use unconventional names internally.

### 2. Automating OSINT and Data Correlation

AI is particularly effective at combing through massive datasets to extract useful information. By automating OSINT (Open Source Intelligence) collection, you can gather public information on `abcxyz.com` from a wide variety of sources such as DNS records, public code repositories, historical data from `Wayback Machine`, and even seemingly mundane mentions on social media.

For instance, you could use an AI-powered script that scrapes data from sources like `VirusTotal`, `CRT.sh` (which provides historical SSL certificate data), or GitHub, and then cross-references those with information from tools like `SecurityTrails` or `Shodan`. AI can then parse through these large datasets to identify patterns or mentions of subdomains, even in contexts where they might not be explicitly listed.

To be more specific, here’s an example prompt you could use for an AI model:

*“Given the dataset collected from `VirusTotal`, `CRT.sh`, `GitHub`, `SecurityTrails`, and `Shodan` for **`abcxyz.com`**, cross-reference all subdomain mentions and identify the ones that are likely related to internal dev or staging environments. Prioritize subdomains that have appeared multiple times or have common development indicators such as `dev`, `test`, `staging`.”*

The AI can then not only compile these results but also help filter and prioritize them based on context. For example, it could highlight mentions that are related to internal environments or dev instances that often hold testing vulnerabilities.

### 3. AI-Powered Integration with Tools like Amass

AI can also be a great way to enhance tools that you may already be using. For example, combining `Amass` with AI-based scripts can help you process its results in a more structured way. Imagine running `Amass` on `abcxyz.com` and then feeding the output into an AI model to:

- Identify key subdomains of interest (e.g., dev environments, customer login portals).
- Sort and prioritize the list based on your needs, such as potential vulnerability or relevance to the business.
- Generate a summary with open ports and detected services for each subdomain.

For instance, you can take Amass output and prompt the AI:

*“Summarize the following Amass subdomain results for **`abcxyz.com`**. Include only those subdomains with open ports 80, 443, and anything related to VPN access.”*

The AI will parse through the often lengthy Amass output and provide you with a well-structured summary that highlights subdomains with active web services, making your next steps much more efficient.

### 4. Clustering Results to Identify Patterns

Subdomains are often named following particular conventions. AI can help analyze and cluster enumerated subdomains to detect patterns that can guide further exploration. Let’s say you’ve found `staging1.abcxyz.com` and `staging2.abcxyz.com` the AI can suggest other potential naming conventions (`staging3`, `staging4`, etc.) based on the pattern it recognizes. This can be incredibly helpful for generating even more leads for subdomains to test.

**Real-Life Example: AI in Action**

Imagine you’re working on `abcxyz.com` and after running the usual tools, you end up with 50 subdomains. By feeding these into an AI, you can quickly prioritize which subdomains have services that might be worth a closer look, like `vpn.abcxyz.com` or `portal.abcxyz.com`, which might indicate points of access to internal systems. The AI could even automate initial port scans and tell you which services seem most promising for further investigation.

This makes your workflow much smoother: you spend less time sifting through potentially hundreds of subdomains and more time focusing on exploiting interesting ones.

**Wrapping It Up**

Using AI for subdomain enumeration isn’t just a fancy trick it’s a practical way to supercharge your pentesting engagements. By automating data collection, enhancing existing tools, and even creatively guessing new subdomains, AI can significantly improve the scope and efficiency of your reconnaissance phase.

Remember, enumeration is just the beginning it's the groundwork for everything else to come. With AI as your partner in crime, you’ll find yourself better prepared and more confident as you move through the later stages of your penetration testing engagements.

Stay tuned for the next episode of "Partners in Crime," where we'll explore more ways that AI can boost your offensive security skills. In the meantime, get out there, give AI a try in your next pentest, and let me know how it goes because even the best hackers could use a good partner in crime!
