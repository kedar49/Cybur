# Cybur: Kernel Module for ARP Poisoning Detection and Prevention

**Cybur** is a **Loadable Kernel Module (LKM)** designed to detect and prevent **ARP Poisoning Attacks**. By intercepting ARP packets and validating their authenticity, Cybur ensures a secure ARP cache by cross-referencing with a dynamically maintained DHCP snooping table.

---

## **Features**

- **Intercept ARP Traffic**: Monitors all ARP requests and responses.
- **Validation Mechanism**: Validates MAC-to-IP bindings before updating the local ARP cache.
- **Dynamic Protection**: Builds and utilizes a runtime DHCP snooping table for real-time verification.
- **Prevent Unauthorized Changes**: Drops invalid ARP packets to prevent ARP spoofing attacks.

---

## **How It Works**

1. **Packet Interception**:
   - Cybur intercepts all ARP requests and responses flowing through the system.

2. **Validation**:
   - Cross-checks the MAC-to-IP bindings in the packet against the bindings in the DHCP snooping table.
   - Ensures only legitimate ARP packets update the local ARP cache.

3. **Prevention**:
   - Invalid ARP packets are immediately dropped, protecting against ARP poisoning attacks.

---

## **Setup and Installation**

### Prerequisites
- Ensure you have kernel headers installed for your current kernel version:
  ```bash
  sudo apt-get install linux-headers-$(uname -r)
  ```
---

1. Build the Kernel Module
To compile the kernel module, use the make command:


```bash
make
```
2. Install the Module
Insert the compiled kernel module into the running kernel:

```bash
sudo insmod cybur.ko
```

3. Remove the Module
To safely remove the kernel module:

```bash
sudo rmmod cybur
```
##Important Notes
Ensure you have root privileges to load and unload kernel modules.
Logs and validation details can be checked in the system log:
```bash
dmesg | tail
```
