
# 01. Create an Azure Resource Group

## 1. What is an Azure Resource Group?

An Azure Resource Group is a logical container used to organise and manage related Azure resources.

For example, our SOC lab uses:
- Windows Virtual Machine
- Log Analytics Workspace
- Microsoft Sentinel
- Data Collection Rules

These resources are organised under a Resource Group called `rg-soc-lab`.

Think of a Resource Group as a folder that holds related resources.

## 2. Why Do We Need a Resource Group?

- **Organisation:** Keeps related Azure resources together.
- **Access Management:** Allows permissions to be assigned at the Resource Group level.
- **Cost Management:** Helps track costs associated with resources.
- **Resource Management:** Allows related resources to be managed together.
- **Policy Management:** Azure policies and tags can be applied at the Resource Group level.

## 3. How Does It Work?

Azure resources are created inside a Resource Group, which belongs to an Azure Subscription.

Our SOC lab follows this structure:

```text
Azure Subscription
        |
        v
   rg-soc-lab
   (Resource Group)
        |
        |---- Windows Virtual Machine
        |
        |---- Log Analytics Workspace
        |
        |---- Other SOC Lab Resources
```

**Note:** Microsoft Sentinel is enabled on the Log Analytics Workspace. It is not a separate virtual machine.

## 4. Resource Group vs Azure Subscription

| Azure Subscription | Resource Group |
|---|---|
| Billing and management boundary | Logical container for resources |
| Can contain multiple Resource Groups | Can contain multiple Azure resources |
| Provides access to Azure services | Organises related resources |
| Resources belong to a subscription | Each resource belongs to one Resource Group |

## 5. Implementation

### Configuration

| Setting | Value |
|---|---|
| Resource Group Name | `rg-soc-lab` |
| Region | Central India |

### Steps

1. Sign in to the [Azure Portal](https://portal.azure.com/).
2. Search for **Resource Groups**.
3. Click **Create**.
4. Select your Azure Subscription.
5. Enter `rg-soc-lab` as the Resource Group name.
6. Select `Central India` as the region.
7. Click **Review + Create**.
8. Click **Create** to deploy the Resource Group.

### Result

The Resource Group `rg-soc-lab` was successfully created.

It acts as the central container for organising the Azure resources used in this SOC lab.

## 6. Important Interview Questions

### Q1. What is an Azure Resource Group?

An Azure Resource Group is a logical container used to organise and manage related Azure resources.

### Q2. Can a Resource Group contain resources from different regions?

Yes. Resources inside a Resource Group can belong to different Azure regions. The Resource Group's location determines where its metadata is stored.

### Q3. Can one resource belong to multiple Resource Groups?

No. An Azure resource can belong to only one Resource Group at a time.

### Q4. What happens when you delete a Resource Group?

Deleting a Resource Group also deletes the resources contained within it. Therefore, deletion must be performed carefully.

### Q5. Is a Resource Group the same as a Virtual Network?

No.

- **Resource Group:** Organises and manages Azure resources.
- **Virtual Network:** Provides network connectivity and isolation for Azure resources.

### Q6. Can we move resources from one Resource Group to another?

Yes. Many Azure resources support moving between Resource Groups, subject to Azure service and dependency restrictions.

### Q7. Is a Resource Group a physical location?

No. It is a logical management container. Its region is used to store its metadata.

## 7. Key Takeaways

- A Resource Group is a logical container, not a physical server.
- It helps organise and manage related Azure resources.
- It supports access control, policy management and cost organisation.
- Every Azure resource belongs to one Resource Group.
- Deleting a Resource Group also deletes its contained resources.
