# JonMon (Beta)
JonMon is a research project I started to help me learn how to code and understand telemetry mechanisms. It is a collection of open-source telemetry sensors designed to provide users with visibility into the operations and activity of their Windows systems. JonMon has a  kernel-level driver component, which is designed to collect information related to system operations such as process creation, registry operations, file creates and more.

In addition to the kernel-level driver component, JonMon also features a user-mode component that collects information about .NET, RPC, network activity, and other important system events. By combining data from both the kernel-level and user-mode components, JonMon provides users with a comprehensive view of their security activity.

The data collected by both components is made easily accessible to users through the Windows event log, allowing users to quickly and easily query the data and gain insights into their system operations. 

JonMon started and will continue to be a researech project that allows for easy telemetry testing and verification.

## Disclaimer
JonMon is currently in Beta release. The project is stable enough to release, but there may be improvements and bugs to fix before V1 is released. Please submit any bug issues as they arise! 

This code is not meant to be ran in production environments and is not guaranteed to work. This is an educational/research project only.

Being that this is a project to help me learn how to code, I understand some things will not be perfect and there will be bugs. Issues are welcome, but may not always be addressed. 

# JonMon Guide
For all things on JonMon, please visit the [wiki](https://github.com/jsecurity101/JonMon/wiki#installation).  

# Credit
This project wouldn't be possible without many great people and projects. A special thank you to the following who had direct impact on this project: 
* Coding Help/Understanding:
  * [Pavel Yosifovich](https://twitter.com/zodiacon)
    * Helping me understand different coding concepts
  * [Evan McBroom](https://twitter.com/mcbroom_evan)
    * General coding help
  * [Connor McGarr](https://twitter.com/33y0re)
    * Helping me understand proper coding practices (especially in the kernel)
  * [Yarden Shafir](https://twitter.com/yarden_shafir)
    * Answering random questions and also hyping me up
* Beta Testers
  * [Roberto Rodriguez](https://twitter.com/Cyb3rWard0g)
  * [Olaf Hartong](https://twitter.com/olafhartong)
  * [Andrew Schwartz](https://twitter.com/4ndr3w6S)
* Courses/Books
  *  [Pavel Yosifovich](https://twitter.com/zodiacon)
      * Kernel Programming Book and Course
      * Pavel's course is what got me interested in this project. A big thank you to him for his teaching! 

