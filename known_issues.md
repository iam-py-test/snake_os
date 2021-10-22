## Known issues with SnakeOS

#### ISSUEID-1
Description: This issue causes a reboot loop after installing packages<br>
Affected versions: <= 0.2<br>
Patched versions: >= 0.3<br>
Workaround: After SnakeOS installs required packages, force-close it via Control-C (or Command-C for MacOS) and then restart it<br>
Status: Fixed in 0.3

#### ISSUEID-2
Description: This issue causes SnakeOS to presist in memory after reboot, thus meaning that two versions of SnakeOS will be running, even though only one is in use<br>
Affected versions: >= 0.3<br>
Patched versions: None (yet)<br>
Workaround: Shutdown SnakeOS completely insted of using the reboot command
Status: awaiting patch
