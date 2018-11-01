# SKREAM

**S**entinelOne's **K**e**R**nel **E**xploits **A**dvanced **M**itigations

This kit contains the following mitigations:
1. Preallocate 0xbad0b0b0
  This mitigation will block exploits using TypeIndex overwrite techniques on Windows 7 and 8 (this specific technique was mitigated by Microsoft in Windows 8.1).

2. PoolSlider and PoolBloater
  Both of these mitigations will randomize pool allocations to break pool overflow exploits.
  PoolSlider uses the extra padding added to non-1-byte-aligned allocations to randomize the start address returned to the caller.
  PoolBloater adds a random number of pool blocks tp each pool allocation, to randomize the size of the received allocation.
 
The mitigations included in SKREAM are explained in detail in these blog posts: 

https://www.sentinelone.com/blog/skream-kernel-mode-exploits-mitigations-rest-us/

The configuration of the driver can be controlled through the config.h file, where you can enable/disable each mitigation and change default values for some of the mitigations.

Notice:
1. You can't enable both PoolBloater and PoolSlider at the same time.
2. If PoolSlider is enabled, the driver can't be loaded early in the boot (start_type= system), since it will conflict with some system drivers and crash the system.
3. Use SKREAM at your own risk!
