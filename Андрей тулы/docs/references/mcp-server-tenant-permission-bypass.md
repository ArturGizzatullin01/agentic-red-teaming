# How I Discovered a Rare Vulnerability in MCP Server

> Источник (сконвертировано из HTML): How I Discovered a Rare Vulnerability in MCP Server _ by 1day _ Medium.html

# How I Discovered a Rare Vulnerability in MCP Server

## INTRODUCTION

Hey all, today I’m back with a writeup on a pretty cool and unique vulnerability I discovered during my security research journey. This was one of the famous public programs on Bugcrowd. Unfortunately, I cannot reveal the name of the company, we’ll refer to it as “REDACTED” or “redacted.com”.

REDACTED is a platform that businesses use to manage all their customer interactions. For teams, it’s basically a central hub where support agents, salespeople, and other team members can collaborate, answer questions, and keep track of conversations. The platform uses a tenant model, which means each company has its own isolated workspace or tenant. For this bug bounty program, we are able to create tenants and assign ourselves any roles, which allows us to test different access levels and permissions.

The platform has too many features, but we should keep note of 2 critical entities in this platform.

**Conversations:** All the messages between team members and customers, which consists of support chats, emails, or other interactions.

**Contacts:** The customers themselves, who can come from anywhere like email, WhatsApp, Instagram, Facebook, websites, and more.

Teams use roles and permissions to manage who can see what, organize contacts, and handle conversations through features like inboxes, threads, and automated workflows.

## Context

I’ve almost spent 2–3 weeks on this target trying to find anything other than duplicates. This was a well-known public program on Bugcrowd, where 5–10 researchers are paid out **daily**, and anything genuine you find is likely considered a duplicate. I even reached a point where I discovered a vulnerability but was lazy to report it because I was 100% sure it would be a duplicate. The main reason is because this application is a closed target, where you don’t have *.redacted.com in-scope to roam around and find hidden stuff. The positive thing is that, I’ve got to know every aspect of this application, every feature, every configuration, what all stuff could go wrong, etc.

After reporting 12 reports, all of which turned out to be duplicates, **I decided to take a step back and think out of the box**. Nothing came to my mind for the first few days. Then I did some deep research on the company, read the latest blogs and looked at new features being rolled out.

## Understanding Roles, Permissions & The Actual Goal

It’s important to understand how access control is implemented in REDACTED. The platform uses a granular permission model where each team member is assigned explicitly defined capabilities that determine which resources they can access and what actions they are allowed to perform.

**can_access_inbox** : *allows the user to access the conversations* (READ-ONLY)

**can_access_contacts** : *allows the user to access every contacts* *(customer information) inside the tenant.* (READ-ONLY)

These are just 2 examples of the permissions out of hundreds of others in this application. Each of these permissions are evaluated independently and must be enabled for the user to interact with the corresponding data.

## My Target

My goal is to read all sensitive conversations and full contact details of every customers in the tenant from a zero-privileged account.

**For those who find it hard to approach applications with a vast number of features, here’s my silly way of approaching it:**

### The CTF Approach

You may think this is silly, but… It is actually… uhm… but this can help you easily find permission bypasses/logic flaws in a closed application.

To do this, first, from a high-privileged account, send a flag to any conversation which the low-privileged account should not be able to access. For example, **FLAG{TH3_BYP455_W0RK3D}** or just “**IF YOU READ THIS, IT WORKED!!**”. This will help you easily identify if a vulnerability was successfully exploited or not.

In my case, I sent a message saying “IF YOU READ THIS, IT WORKED!!” from the admin account to a customer.

And for accessing the contacts, I added a new contact to the tenant (not a team member, it’s a customer contact) with the name “**Jack Bugcrowd**”

Let’s try accessing both of these flags from our low-privileged account normally…

NOPE! As expected. Now my end goal is to retrieve the flags from the restricted conversations and contact data.

But how??

## The Turning Point

After hours of googling, I found something very interesting. The company had recently rolled out a new **MCP server integration** **for the tenants**, which allows the team members to connect an MCP Server to their account and integrate it with any LLM (Claude, Copilot, Cursor, etc). This is not something any other researcher can find within the application itself. It should be manually done by the instructions provided in that blog I found. So I thought, why not give it a try…

## What’s an MCP Server?

MCP servers are programs that use the Model Context Protocol (MCP) to expose capabilities like tools and data to AI agents and LLMs. MCP servers are very similar to the APIs we usually hear about. They’re basically a bridge between an AI model and external services, which allows the AI to interact with things like databases, filesystems, APIs, and other data sources to perform tasks and retrieve information.

In an MCP server, there are several tools you can use to fetch/perform different tasks. *A tool is like a function in a programming language, where you sometimes need to provide an argument to perform an action and it returns some data in a specific format.* (For example, a tool to fetch full customer details using their ID/name)

In our case, the MCP server allows us to access the platform’s internal data, such as **conversations** and **contacts**, using various tools, and pass that information to AI models to perform different kinds of tasks. It acts like a flexible bridge that allows the AI models to read, process, and work with data that would normally stay inside the application.

## Setting up the MCP Server

To be honest, this part was by far the hardest in the entire process, which is probably why very few people even try out this feature.

For this demonstration, I’m using [mcp-client-and-proxy](https://github.com/appsecco/mcp-client-and-proxy) tool by [Appsecco](http://appsecco.com) which I came across while watching [this wonderful masterclass on MCP Pentesting](https://youtu.be/aetmfPUuqms?si=bQYPNW-QtCkps-VY) by [Mr Riyaz Walikar](https://www.linkedin.com/in/riyazw/). This tool helps us to proxy the requests between our MCP client and the server, which allows us to view the raw HTTP requests using Burpsuite.

To set this up, first we need **mcp_config.json** file which basically holds the start command for the MCP client.

```
{
  "mcpServers": {
    "REDACTED": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://mcp.redacted.com/mcp"
      ]
    }
  }
}
```
Having this **mcp_config.json** in the root directory of the mcp-client-and-proxy tool, we can just run:

`python3 app.py --start-proxy`
Once you run this tool, it will redirect you to the REDACTED’s authorization page, where you should authorize the MCP application to our tenant.

## Attack Plan & Logic

At this point, you might be wondering why I walked you through the entire MCP setup process without showing how any of this turns into an actual vulnerability.

This is where a very simple question popped into my head.

If the platform lets me connect an MCP server to my account, what permissions does that MCP application actually inherit? Does it strictly follow the same restrictions as my low-privileged user, or does it behave like a separate trusted entity with broader access?


So I thought, why not try accessing the same restricted conversations and contact data through the MCP server instead of the normal application interface? If this MCP integration is treated differently behind the scenes, this could reveal something very interesting.

## The Vulnerability

With the MCP application connected to my low-privileged account, let’s try calling different tools and see if we can access anything sensitive.

`python3 app.py --start-proxy`
From these tools, we can simply enter the ID of the tool we want to call, In our case we’re gonna call the tool called “search” which has ID 5.

From the MCP server documentation of REDACTED, it’s stated that the “search” tool expects us to pass a DSL query (Used in ElasticSearch) in the format:

`object_type:conversations``object_type:contacts`
Also we can pass in various complex subqueries to filter out the results we need:

`object_type:conversations state:open source_type:email source_subject:contains:"billing"`
Let’s try running the first query “object_type:conversations”, capture the request in burpsuite and see if we can pull out every conversation in the tenant (Which we definitely should NOT have access to):

To my surprise, the response returned all conversation IDs across the tenant (though not the actual message contents), which is still a critical issue.

Now using the retrieved conversation ID “conversation_215471608702639”, let’s try calling the “**fetch**” tool which essentially will retrieve the whole conversation, just by using the ID.

BOOOM!! We got the flag!! Which means, the bypass successfully worked!

Let’s also try accessing the contact flag we made before using the query:

`object_type:contacts name:Jack`
This will look for any contacts named “Jack”

WE GOT BOTH!!

I was successfully able to access both restricted conversations and contacts in the tenant.

The vulnerability also affected each and every tool in that MCP server, where you can essentially query any objects (Conversations or Contacts) from the tenant without having any permission.

**To my surprise, this permission bypass worked even after removing the attacker from the tenant, which indicates that the MCP application is a separate entity and not linked to the user in any way, even though it was set up on behalf of the user.**

## In Short

We basically used the MCP Server as an indirect way to get around the platform’s permissions. Even though the account had limited access, the MCP integration was able to see things it shouldn’t, showing that it wasn’t following the same restrictions as the user. Which ended up revealing a clear permission bypass.

## The Exploit

For an impactful PoC, I’ve created a 0 click exploit which will automatically fetch every conversations and contacts from the tenant and save it to text files.

## Conclusion

This writeup is more about sharing my thought process than just the bug itself. It shows how looking at things differently and exploring overlooked features can lead to unique findings.

After reporting this vulnerability, I was 100% sure that this will NOT be a duplicate, not because it was something magical, but because setting everything up and testing each tool one by one takes a serious amount of patience, something I honestly think most hunters would give up on halfway through.


No wonder, it wasn’t a duplicate, and I ended up getting paid for it. Proof that persistence and out-of-the-box thinking really do pay off.
