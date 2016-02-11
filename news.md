## ::201602 / news::

### sec

+ [Intelligence-Driven Incident Response with YARA](https://www.sans.org/reading-room/whitepapers/forensics/intelligence-driven-incident-response-yara-35542)
__sec,methodologie__

> Given the current cyber threat landscape, organizations are now beginning to acknowledge the inexorable law
that decrees that they will be compromised. Threat actors' tactics, techniques, and procedures demand
intelligence-driven incident response, which in turn, depend upon methodologies capable of yielding actionable
threat intelligence in order to adapt to each threat. The process to develop such intelligence is already in
motion, heavily relying on behavioral analysis, and has given birth to cyber threat indicators...

+ [Image size issues for Burp Suite](https://github.com/silentsignal/burp-image-size)
__burp,plugin__

> When serving image assets, many web developers find it useful to have a feature that scales the image to a size specified in a URL parameter. Such functionality can not only be used for scaling images down but also making them huge, this leads to Denial of Service (DoS). This Burp plugin that can be loaded into Extender, and passively detects if the size of an image reply is included in the request parameters.

+ [Angler EK leads to fileless Gootkit](http://www.cyphort.com/angler-ek-leads-to-fileless-gootkit/)
__malware,analysis__

> On January 27, 2016 Cyphort Labs discovered a site infected with Angler EK leading to a fileless Gootkit (a.k.a. XswKit) malware. The site was redirecting visitors to the malware through a compromised OpenX Ad server injecting a malicious iframe into the page. The iframe leads to Angler EK which downloads Bedep ad-fraud which then downloads a Gootkit loader. 

+ [REMNUX V6 FOR MALWARE ANALYSIS (PART 2): STATIC FILE ANALYSIS](http://malwology.com/2016/02/09/remnux-v6-for-malware-analysis-part-2-static-file-analysis/)
__malware,analysis__

> In this post, we’ll continue exploring some of the helpful capabilities included in REMnux v6. Be sure to regularly update your REMnux VM by running the command update-remnux.

+ [Shellsploit](https://github.com/b3mb4m/shellsploit-framework)
__shellcode__

> Shellsploit let's you generate customized shellcodes, backdoors, injectors for various operating system. And let's you obfuscation every byte via encoders.

+ [How to isolate VBS or JScript malware with Visual Studio](http://www.welivesecurity.com/2016/02/11/isolate-vbs-jscript-malware-visual-studio/)
__malware,analysis,vbs,js__

> In recent years, the ESET Latin America Investigation Laboratory has witnessed a growth in malware developed using scripting languages. This is why we now want to demonstrate how to configure a dynamic analysis environment to isolate such threats so we can understand and observe their behavior in a controlled environment.

+ [NetworkOpenedFiles v1.00](http://www.nirsoft.net/utils/network_opened_files.html)
__tools,windows__

> NetworkOpenedFiles is a simple tool for Windows that displays the list of all files that are currently opened by other computers on your network. For every opened filename, the following information is displayed: Filename, user name, computer name (On Windows 7/2008 or later), Permissions information (Read/Write/Create), locks count, file owner, file size, file attributes, and more...

+ [From zero to SYSTEM on full disk encrypted Windows system (Part 1)](https://blog.ahmednabeel.com/from-zero-to-system-on-full-disk-encrypted-windows-system/)
__windows,disk,encryption__

> Whether you want to protect the operating system components or your personal files, a Full Disk Encryption (FDE) solution allows you to keep track of the confidentiality and integrity. One of the most commonly used FDE solutions is Microsoft Bitlocker®, which due to its integration with the Trusted Platform Module (TPM) as well as the Active Directory environment makes it both user-friendly and manageable in a corporate environment. 
When the system is protected with a FDE solution, without a pre-boot password, the login or lock screen makes sure attackers with physical access are not able to gain access to the system. 

+ [The hype about Crypter is misplaced and overall dangerous](http://colin.keigher.ca/2016/02/the-hype-about-crypter-is-misplaced-and.html)
__crypter,analysis__

> My problem with cryptography boils down to this: every once in a while, someone comes along claiming that they have a system or software that will revolutionize everything. Naturally, a media frenzy ensues with minimal fact checking. The security industry then catches wind of it, and it is quickly and thoroughly demonstrated to be a pile of vaporware garbage. Then we collectively discover that the enterprising individual has also managed to secure a hefty amount of funding and has spent most of it on a swank office and catered lunches.

+ [The Difference Between Red, Blue, and Purple Teams](https://danielmiessler.com/study/red-blue-purple-teams/)
__sec,opinion__

> There is some confusion about the definitions of Red, Blue, and Purple teams within Information Security. Here are my definitions and concepts associated with them.

+ [PoC k GTFO 8](https://www.alchemistowl.org/pocorgtfo/pocorgtfo08.pdf)
__fanzine__

+ [The Social-Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit)
+ [trustedsec](https://www.trustedsec.com/february-2016/set-v7-0-remembrance-released/)
__socialengineering,tools,set__

> The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. SET has a number of custom attack vectors that allow you to make a believable attack quickly. SET is a product of TrustedSec, LLC – an information security consulting firm located in Cleveland, Ohio.

+ [Stratosphere IPS Project](https://stratosphereips.org)
__tools,ips__

> The Stratosphere IPS is a free software Intrusion Prevention System that uses Machine Learning to detect and block known malicious behaviors in the network traffic. The behaviors are learnt from highly verified malware and normal traffic connections in our research laboratory. Our goal is to provide the community and specially the NGOs and CSOs with an advanced tool that can protect against targeted attacks.

+ [Hijacking forgotten & misconfigured subdomains](http://www.xexexe.cz/2016/02/hijacking-forgotten-misconfigured.html)
__sec,tool,dns,hack__

> Hey netsec folks, it's been a while since my last blog post, so I decided to release a new tool ;)
I think that we need more articles about "DNS hacking", I hope that you will learn something new here.

+ [Tidas: a new service for building password-less apps](http://blog.trailofbits.com/2016/02/09/tidas-a-new-service-for-building-password-less-apps/)
__passwordless,service__

> For most mobile app developers, password management has as much appeal as a visit to the dentist. You do it because you have to, but it is annoying and easy to screw up, even when using standard libraries or protocols like OAUTH.

+ [The many ways of handling TCP RST packets](https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/)
__network,tcp,rst__

> What could be a simpler networking concept than TCP's RST packet? It just crudely closes down a connection, nothing subtle about it. Due to some odd RST behavior we saw at work, I went digging in RFCs to check what's the technically correct behavior and in different TCP implementations to see what's actually done in practice.

+ [Deviare-InProc](https://github.com/nektra/Deviare-InProc)
__intercept,analysis,binary__

> The library is coded in C++ and provides all the facilities required to instrument binary libraries during runtime. It includes support for both 32 and 64 bit applications and it implements the interception verifying different situations that can crash the process. If you need to intercept any Win32 functions or any other code, this library makes it easier than ever.

+ [randkit-random-number-rootkit](#)

>

+ [FIND VULNERABLE ROUTERS AND DEVICES ON THE INTERNET](http://securityblog.gr/3247/find-vulnerable-routers-and-devices-on-the-internet/)
__pentest,scan,router,network__

> The Routerhunter is an automated security tool que finds vulnerabilities and performs tests on routers and vulnerable devices on the Internet. The Routerhunter was designed to run over the Internet looking for defined ips tracks or random in order to automatically exploit the vulnerability DNSChanger on home routers.

+ [Adblocking for Internet Explorer without an extension: Enterprise deployment](http://decentsecurity.com/enterprise/#/adblocking-for-internet-explorer-deployment/)
__windows,adblock,enterprise__

> Blocking advertising has multiple security and performance benefits to clients. Ads are especially dangerous to corporate computers, which often run outdated plugins that can be exploited by malvertising. Most people immediately jump to thinking they need Firefox or Chrome to do this. However, did you know Internet Explorer has adblocking built-in? The feature is called "Tracking Protection Lists," and while not as powerful as a full adblocking extension, it is very effective.

+ [Confirmation of a Coordinated Attack on the Ukrainian Power Grid](https://ics.sans.org/blog/2016/01/09/confirmation-of-a-coordinated-attack-on-the-ukrainian-power-grid)
__ukrain,powergrid,attack__

> After analyzing the information that has been made available by affected power companies, researchers, and the media it is clear that cyber attacks were directly responsible for power outages in Ukraine. The SANS ICS team has been coordinating ongoing discussions and providing analysis across multiple international community members and companies. We assess with high confidence based on company statements, media reports, and first-hand analysis that the incident was due to a coordinated intentional attack.

+ [MadProtect, not that mad](http://www.cert.pl/news/11073)
__madprotect,malware,netwire,packer__

> Some weeks ago we stumbled on a packer that our tools could not break. Surprisingly, this is actually not that common since most of the malware in the wild uses some sort of RunPE technique which is relatively trivial to break using simple memory tracing.

+ [keybase](https://keybase.io/)
__secure,service__

> Keybase is more than a website. If you're comfortable working in a terminal, you should install the keybase command line program. You can do so much with it: sign, verify, encrypt, generate messages, sign code, move keys around, etc., all using GPG for the crypto.

+ [BSIDESTO 2015 - NICK ALEKS - WEAPONS OF A PENTESTER](https://www.youtube.com/watch?v=lDvf4ScWbcQ)
__pentest,physic,network,video__

> Nick Aleks is a professional ethical hacker and demonstrates physical tools and devices that he uses for penetration testing.

+ [Under the Hood of Cryptowall 4.0](http://www.tripwire.com/state-of-security/security-awareness/under-the-hood-of-cryptowall-4-0/)
__malware,reverse__

+ [What Have We Learned From This Open Source Project?](http://taskwarrior.org/docs/advice.html) 
__opensource__

+ [PoC || GTFO 0x04](https://archive.org/stream/pocorgtfo04/pocorgtfo04_djvu.txt)
__reverse,zine__

+ [Deserialization in Perl v5.8](http://www.agarri.fr/kom/archives/2016/02/06/deserialization_in_perl_v5_8/index.html)    __pentest,perl,reverse__

### sys
+ [Creating containers - Part 1](http://crosbymichael.com/creating-containers-part-1.html)

> This is part one of a series of blog posts detailing how docker creates containers. We will dig deep into the various pieces that are stitched together to see what it takes to make docker run ... awesome.

### dev

+ [libsalamander](https://github.com/SilentCircle/libsalamander)
__silentcircle,salamander,protocol,messaging__

> Salamander is a secure messaging protocol for mobile devices. It uses the Axolotl Ratchet designed by Trevor Perrin and Moxie Marlinspike.

+ [rust](https://www.rust-lang.org)
__python__

> Rust is a systems programming language that runs blazingly fast, prevents segfaults, and guarantees thread safety. 

+ [trace – Follow Python statements as they are executed](https://pymotw.com/2/trace/)
__python,debug,trace__

### arch
+ [Build Your Own (Cross-) Assembler....in Forth](http://www.bradrodriguez.com/papers/tcjassem.txt)

> In a previous issue of this journal I described how to
  "bootstrap" yourself into a new processor, with a simple
  debug monitor.  But how do you write code for this new CPU,
  when you can't find or can't afford an assembler?  Build
  your own!

+ [Blog: How do Win 3.1 applications work in Wine?](http://www.wine-staging.com/news/2016-02-10-blog-wine-16bit.html)

> If you read our release notes frequently, you might have noticed that I tend to explain the background behind the changes in Wine Staging as I imagine that this might be interesting for some of our readers. However, those explanations do not really belong into the release notes, so I decided to move them to separate blog posts. So welcome to my first blog post in which I explain how the 16 bit support works in Wine and which typical bugs you may encounter. I hope you enjoy reading it although it is going to be very technical, but maybe you learn something from it :-).

+ [The microarchitecture of Intel, AMD and VIA CPUs](http://www.agner.org/optimize/microarchitecture.pdf)
__cpu,arch,intel,amd,via,pdf__

> An optimization guide for assembly programmers and compiler makers
+ [BITS](http://biosbits.org/)
__bios,boot,preos__

> The Intel BIOS Implementation Test Suite (BITS) provides a bootable pre-OS environment for testing BIOSes and in particular their initialization of Intel processors, hardware, and technologies. BITS can verify your BIOS against many Intel recommendations. In addition, BITS includes Intel's official reference code as provided to BIOS, which you can use to override your BIOS's hardware initialization with a known-good configuration, and then boot an OS.

### electronic

+ [electronics Forrest Mims engineer's mini notebook 555 timer circuits (radio shack electronics)](https://archive.org/details/electronics_-_Forrest_Mims-engineers_mini-notebook_555_timer_circuits_radio_sha)
> electronics Forrest Mims engineer's mini notebook 555 timer circuits (radio shack electronics)
