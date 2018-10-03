# NAGuard
Architecture and Design
Overview
The architecture of naGuard consists of two main components, naGuard I/O Monitor and naGuard Analyzer.
naGuard I/O Monitor: 
a Windows kernel module [mini-filter driver] which monitors and logs every single I/O operation in the system. The information is passed to naGuard Analyzer for analysis.
naGuard Analyzer: 
a user mode application which analyzes all the data received from naGuard I/O Monitor, detects and stops malicious behavior.



Introduction to Windows I/O System
Since naGuard I/O Monitor operates at the core of the operating system, the kernel, it is crucial to quickly introduce some relevant concepts of the internals of Windows operating system. 
The Windows I/O system consists of several executive components that together manage hardware devices and provide interfaces to hardware devices for applications and the system. We’ll only cover the components that make up the I/O system, including the I/O manager as they are crucial. 
To implement these features the Windows I/O system consists of several executive components as well as device drivers, which are shown in the above figure.
■ The I/O manager is the heart of the I/O system. It connects applications and system components to virtual, logical, and physical devices, and it defines the infrastructure that supports device drivers.
■ A device driver typically provides an I/O interface for a particular type of device. A driver is a software module that interprets high-level commands, such as read or write, and issues low level, device-specific commands, such as writing to control registers. Device drivers receive commands routed to them by the I/O manager that are directed at the devices they manage, and they inform the I/O manager when those commands are complete. Device drivers often use the I/O manager to forward I/O commands to other device drivers that share in the implementation of a device’s interface or control.
 
naGuard Analyzer
Multithreaded scoring table which grant higher scoring to malicious behavior processes. 
 
•	DB:
o	Several criteria:
	I/O operations: Read, write, rename.
	short (3 sec) aggregation and long (process life) time aggregation. 
	Absolute and relative entropy.
	Write OP - New file creation and rewrite existing file.
•	Score engine:
o	Increase score for suspicions behavior and decrease score for innocent behavior through time. 
o	Interesting extensions = content holding files – doc, pdf etc.
•	Hidden honey pots in several locations (as result of research been done) and names.



Main Data structures:
1.	filter_message_t – message received from kernel – Contains the following fields:
a.	Opcode – can hold:
i.	0 – new write. 
ii.	1 – rewrite
iii.	2 – rename
iv.	3 – delete
b.	Process_id 
c.	Preop_entropy – entropy before I/O operation take place.
d.	Postop_entpry – in case of write operation – entropy value after operation took place.
e.	Preop_filename – file name before I/O operation take place.
f.	Postop_filename - in case of rename operation – file name after operation took
 			
2.	DB:
a.	unordered_map<HANDLE, ThreadInfo>
b.	ThreadInfo is capable of handle all data related to specific process.
i.	M_score – current malicious score.
ii.	honeyPotsCounter – counter of honey pots touched by process in the last X seconds (X=3).
iii.	Write_end_entropy – sum of absolute entropy in rewrite operations.
iv.	Write_delta_entropy – sum of delta entropy in rewrite operations.
v.	New_write_entropy – sum of entropy in new write operations.
vi.	notExtInListWrite – number of all write operations (include all extensions) in the last X seconds (X=3) if absolute entropy higher then 3.5.
vii.	honey_pots_touched – number of honey pots files touched (all OPS)
viii.	m_total_ops[OPS_NUM] – number of all operations (interesting extensions only) in the last X seconds (X=3).
ix.	 m_ops[OPS_NUM] – number of all operations (interesting extensions only) in the process life.


Scoring algorithm:

The algorithm is based on division of ransomware behavior into 3 types:
1.	Ransomware which copy the original file content into memory, encrypting the content, create new file and write encrypted content into it, and then delete original file.
2.	Ransomware which encrypting the files as is and change extension to another ext.
3.	Ransomware which encrypting the files as is without change extension.
For each type there is part of the algorithm which should take care:
For type 1 – 
1.	+ 5 points for write of more than 30 files (include all extensions if absolute entropy higher then 3.5) in last 3 seconds (if not -2).
2.	+ 5 points for delete of more then 10 files in last 3 seconds (just "interesting" extensions) (if not -1)
For type 2 – 
1.	+ 5 points for rewrite of more than 10 "interesting" files, if average absolute entropy higher than 3.2 than +10.
2.	 + 5 points for rename of more than 10 "interesting" files, if average absolute entropy higher than 3.2 than +10.
For type 3 – 
1.	+ 5 points for rewrite of more than 10 "interesting" files, if average absolute entropy higher than 3.2 than +10.
For all types – 
1.	+ 10*number of honey pots touched.
2.	
The algorithm was tuned experimentally.
If total score of process is higher then 100 and the process is not signed it would be terminated.
  		
Tests and Results
Security solutions benchmarked based on four main parameters: detection accuracy, false positive rate, system stability and overhead [performance hit].
To test detection accuracy, we infected a system with several known ransomware. Below are the results:
1.	WannaCry – naGuard successfully detected and stopped malicious processes. Detection occurred within seconds [5-10] after infection.
2.	Jigsaw – naGuard successfully detected and stopped malicious processes. Detection occurred within seconds [5-10] after infection.
3.	Satana - naGuard successfully detected and stopped malicious processes. Detection occurred within seconds [5-10] after infection.
4.	Vipassana - naGuard successfully detected and stopped malicious processes. Detection occurred within seconds [5-10] after infection.
5.	Cerber -  naGuard successfully detected the threat, however it was unable to neutralize it. Cerber injected a malicious code to system processes, and we could not figure out a way to stop execution of malicious code without compromising system stability. After keeping me awake for several nights without having any progress, I decided to check what solutions the industry can offer for these types of threats. I tried the following solutions: ZoneAlarm [CheckPoint], RansomFree [Cybereason], Malwarebyte Anti-Ransomware [Malwarebytes].
All of the above solutions failed to stop Cerber, and the Malwarebytes anti-Ransomware failed to detect it.

Testing for false positives:
1.	Performing Windows update – no false positives.
2.	Installing several applications [Dropbox, Visual Studio Code, 7Zip, Google Chrome] – no false positives.
3.	Archiving and unarchiving several files using 7Zip – no false positives.

To test system stability, the following was done:
1.	Opening huge files.
2.	Copying huge files.
3.	Running disk benchmarking software [crystal disk mark].
4.	Using the machine for several hours with typical usage [browsing, text editing, installing\uninstalling applications]
5.	Leaving the machine on overnight.
Not a single crash [BSOD] was observed.

