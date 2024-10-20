# Burp Suite Extensions by El Mago

Welcome to my collection of Burp Suite extensions! This repository features a variety of tools designed to enhance and expand the capabilities of Burp Suite. Here, you'll find both my custom-built extensions and modified versions of popular existing ones, each tailored to provide additional functionalities and improve your testing workflow.

**Disclaimer:** 
_Most of the code was written by artificial intelligence. I don’t claim to have developer skills, just prompt writing skills xD_

## Features:

- **Custom Extensions**: Unique tools I've developed to address specific needs or improve upon existing functionalities within Burp Suite.
- **Enhanced Existing Extensions**: Modified versions of well-known Burp Suite extensions with added features to boost their performance and usability.
- **Detailed Documentation**: Comprehensive guides and examples for each extension to help you integrate them seamlessly into your Burp Suite setup.
- **Open Source Collaboration**: Contributions are welcome! Feel free to fork, modify, and propose changes to further enhance these tools.

## Getting Started:

1. **Installation**: Download and import ("Add") the extension in your "Extensions" tab in Burp Suite.

## Extensions Included:

### BurpLinkFinder
**BurpLinkFinder** is a powerful Burp Suite extension designed for passive scanning of JavaScript files to uncover endpoint links. This tool simplifies the process of identifying potentially interesting endpoints within your web application's JavaScript files, making it an essential addition to your security testing toolkit. (Credits to https://github.com/PortSwigger/js-link-finder)

Additional Enhancements:
- **Dynamic Search Filter**: A dynamic filter feature that allows you to refine the search results in real-time, making it easier to focus on the most relevant links.
- **Scope Matching Checkbox**: An option to display only the results that match the defined scope in Burp Suite, ensuring that you see only the links pertinent to your current testing scope.

### salesforce-aura.py (Burp Suite Lightning)
A Python-based version of the original Salesforce Lightning extension for Burp Suite, updated to work with the latest stable version of Burp Suite Pro (2024.8.5). Originally written in Java:
[https://github.com/salesforce/lightning-burp](https://github.com/salesforce/lightning-burp)

### facebook_request_cleaner.py
A request minimizer for Facebook that cleans unused cookies and decodes parameters in a more readable format, removing unnecessary ones.
