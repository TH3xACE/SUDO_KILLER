# Change Log
All notable changes to the project SUDO_KILLER will be documented in this file.
 

## [Version 2] - 2023
 
### Added
 - Display Timestamp (amount of time in minutes between instances of sudo before it will re-prompt for a password) was added.
 - Detection CVE-2023-22809 was added
 - Exploit for CVE-2023-22809 was added
 - Video showing exploitation of CVE-2023-22809 was added
 - Adding excessive sudo rights check - implies a user is root
 - Adding check for MITRE Attack TTP T1548.003 (sudo caching)

### Changed
 
### Fixed
  - Bug Correction


## [Version 2] - 2021
 
### Added
 - Exploit for CVE-2021-3156 was added
 - Detection for CVE-2021-3156 was added
 - Detection for CVE-2021-23240 was added
 - Exploit for CVE-2019-18634 was added
 - Docker environment to test CVE-2019-18634 was added
 - Video showing exploitation of CVE-2019-18634 was added
 - Video showing exploitation of CVE-2021-3156 was added
 - New dangerous bins added (more than 70)
 
### Changed
 
### Fixed
  - Arguments bug correction


## [Version 2] - 2020-02-11
 
### Added
 - New checks and/or scenarios : CVE-2019-14287 - runas
 - New checks and/or scenarios : No CVE yet - sudoedit - absolute path
 - New checks and/or scenarios : CVE-2019-18634 - pwfeedback
 - New checks and/or scenarios : User Impersonation
 - New checks and/or scenarios : list of users in sudo group
 - Testing environment : A docker to play with the tool and different scenarios, you can also train on PE.
 - New functionality: offline mode - ability to extract the required info from audited system and run SK on host.
 - New videos
   
### Changed
  - Continous improvement of the way output presented
 
### Fixed
  - Performance improved
  - Bugs corrected (checks, export, report,...)
  - Annonying password input several time removed

