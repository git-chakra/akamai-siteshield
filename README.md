Akamai CIDR Updater for AWS Security Groups
=====================================================

**Overview**
------------

This script updates AWS security groups with the latest Akamai CIDR blocks. It retrieves the latest CIDR blocks from Akamai, describes security groups with a specific tag, and updates the security groups with the new CIDR blocks.

**Prerequisites**
---------------

* Python 3.x
* `requests` library
* `boto3` library
* `akamai.edgegrid` library
* AWS credentials set up on your machine
* Akamai edgerc file set up on your machine

**How it Works**
----------------

Here is a high-level overview of how the script works:

1. The script retrieves the latest Akamai CIDR blocks using the `akamai_getcidr` function.
2. It describes security groups with the tag `SecureCIDRs` and value `Akamai AutoUpdate` using the `describe_security_groups` function.
3. For each security group, it retrieves the current CIDR blocks using the `get_cidronSG` function.
4. It removes the existing CIDR blocks from the security group using the `revoke_security_group_ingress` method.
5. It adds the new CIDR blocks to the security group using the `authorize_security_group_ingress` method.

**Functions**
-------------

### `akamai_getcidr`

Retrieves the latest Akamai CIDR blocks.

### `describe_security_groups`

Describes security groups with the tag `SecureCIDRs` and value `Akamai AutoUpdate`.

### `get_cidronSG`

Retrieves the current CIDR blocks for a security group.

### `update_security_groups`

Updates all security groups with the latest Akamai CIDR blocks.

**Diagram**
-----------
```mermaid
graph TD;
    A[Akamai API] -->|retrieve CIDR blocks|> B[akamai_getcidr];
    B -->|describe security groups|> C[describe_security_groups];
    C -->|get current CIDR blocks|> D[get_cidronSG];
    D -->|update security groups|> E[update_security_groups];
```

**Usage**
---------

1. Install the required libraries using `pip install requests boto3 akamai.edgegrid`.
2. Set up your AWS credentials and Akamai edgerc file on your machine.
3. Run the script using `python script.py`.
4. The script will update all security groups with the latest Akamai CIDR blocks.

**Note**
-----

This script assumes that you have the necessary permissions to update security groups in your AWS account. Additionally, you should test the script in a non-production environment before running it in production.
