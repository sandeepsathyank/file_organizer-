I’m sandeep, and today I’ll be presenting my project FileGuard Organizer — an advanced file management and security system built with Python Flask.
It automatically organizes your files and also protects your system by scanning them for viruses using ClamAV.”

________________________________________
🎯 Purpose
The main goal of FileGuard Organizer is to:
•	Automatically organize files based on their type or extension.
•	Scan and quarantine infected files using ClamAV Antivirus before any file operation.
•	Provide a user-friendly web interface to manage file organization tasks safely and visually.
________________________________________
⚙️ Key Features
1.	🔒 ClamAV Integration (Security First)
o	Scans files and folders for viruses or malware before organizing.
o	Automatically quarantines infected files to prevent system harm.
2.	📂 Intelligent File Organization
o	Automatically categorizes files into folders such as Images, Documents, Videos, Audio, Code, Archives, etc.
o	Supports custom categories defined by the user via the configuration panel.
3.	🧠 Scan without organize
o	It will scan without moving 
4.	🗃️ Archive Mode
o	Organizes files into subfolders based on their year and month of modification (e.g., Documents/2025/11).
5.	🔁 Recursive Mode
o	Scans and organizes files in subdirectories as well.
6.	🧹 Empty Folder Cleanup
o	Deletes empty directories after files are moved to maintain a clean folder structure.

7.	⚙️ Custom Configuration
o	Users can add or edit file categories and specify which extensions belong to which category.
o	Configuration is saved in config.json for persistent customization.
8.	💬 Built-in AI Chatbot Assistant
o	A friendly chatbot guides users about app features like “scan mode,” “archive mode,” and “virus scan.”
________________________________________
🏗️ Technology Stack
Component	Technology Used
Backend	Python (Flask Framework)
Frontend	HTML, Tailwind CSS, JavaScript
Database / Config	JSON file-based configuration (config.json)
Antivirus Engine	ClamAV (via clamd Python library)
FileGuard Organizer is not just a file sorting tool — it’s a complete solution that combines automation and security.
It helps users save time, stay organized, and keep their systems protected.”
