#include <ntifs.h>
#include "NativeStructs7.h"
#include "NativeStructs8.h"

enum MM_MAX_COMMIT : ULONG_PTR {
    Windows7 = 0x7ffffffffffff,
    Windows8 = 0x7fffffff,
};

static constexpr ULONG VAD_EVENT_BLOCK_POOL_TAG = 'MmSe';

namespace win7 {
    TABLE_SEARCH_RESULT
        MiFindNodeOrParent(
            _In_ PMM_AVL_TABLE Table,
            _In_ ULONG_PTR StartingVpn,
            _Out_ PMMADDRESS_NODE * NodeOrParent
        )

        /*++

        Routine Description:

        This routine is used by all of the routines of the generic
        table package to locate the a node in the tree.  It will
        find and return (via the NodeOrParent parameter) the node
        with the given key, or if that node is not in the tree it
        will return (via the NodeOrParent parameter) a pointer to
        the parent.

        Arguments:

        Table - The generic table to search for the key.

        StartingVpn - The starting virtual page number.

        NodeOrParent - Will be set to point to the node containing the
        the key or what should be the parent of the node
        if it were in the tree.  Note that this will *NOT*
        be set if the search result is TableEmptyTree.

        Return Value:

        TABLE_SEARCH_RESULT - TableEmptyTree: The tree was empty.  NodeOrParent
        is *not* altered.

        TableFoundNode: A node with the key is in the tree.
        NodeOrParent points to that node.

        TableInsertAsLeft: Node with key was not found.
        NodeOrParent points to what would
        be parent.  The node would be the
        left child.

        TableInsertAsRight: Node with key was not found.
        NodeOrParent points to what would
        be parent.  The node would be
        the right child.

        Environment:

        Kernel mode.  The PFN lock is held for some of the tables.

        --*/

    {
        PMMADDRESS_NODE Child;
        PMMADDRESS_NODE NodeToExamine;
        PMMVAD_SHORT    VpnCompare;
        ULONG_PTR       startVpn;
        ULONG_PTR       endVpn;

        if (Table->NumberGenericTableElements == 0) {
            return TableEmptyTree;
        }

        NodeToExamine = (PMMADDRESS_NODE)GET_VAD_ROOT(Table);

        for (;;) {

            VpnCompare = (PMMVAD_SHORT)NodeToExamine;
            startVpn = VpnCompare->StartingVpn;
            endVpn = VpnCompare->EndingVpn;

#if defined( _WIN81_ ) || defined( _WIN10_ )
            startVpn |= (ULONG_PTR)VpnCompare->StartingVpnHigh << 32;
            endVpn |= (ULONG_PTR)VpnCompare->EndingVpnHigh << 32;
#endif  

            //
            // Compare the buffer with the key in the tree element.
            //

            if (StartingVpn < startVpn) {

                Child = NodeToExamine->LeftChild;

                if (Child != NULL) {
                    NodeToExamine = Child;
                }
                else {

                    //
                    // Node is not in the tree.  Set the output
                    // parameter to point to what would be its
                    // parent and return which child it would be.
                    //

                    *NodeOrParent = NodeToExamine;
                    return TableInsertAsLeft;
                }
            }
            else if (StartingVpn <= endVpn) {

                //
                // This is the node.
                //

                *NodeOrParent = NodeToExamine;
                return TableFoundNode;
            }
            else {

                Child = NodeToExamine->RightChild;

                if (Child != NULL) {
                    NodeToExamine = Child;
                }
                else {

                    //
                    // Node is not in the tree.  Set the output
                    // parameter to point to what would be its
                    // parent and return which child it would be.
                    //

                    *NodeOrParent = NodeToExamine;
                    return TableInsertAsRight;
                }
            }

        };
    }
}

namespace win8 {
    TABLE_SEARCH_RESULT
        MiFindNodeOrParent(
            _In_ PMM_AVL_TABLE Table,
            _In_ ULONG_PTR StartingVpn,
            _Out_ PMMADDRESS_NODE * NodeOrParent
        )

        /*++

        Routine Description:

        This routine is used by all of the routines of the generic
        table package to locate the a node in the tree.  It will
        find and return (via the NodeOrParent parameter) the node
        with the given key, or if that node is not in the tree it
        will return (via the NodeOrParent parameter) a pointer to
        the parent.

        Arguments:

        Table - The generic table to search for the key.

        StartingVpn - The starting virtual page number.

        NodeOrParent - Will be set to point to the node containing the
        the key or what should be the parent of the node
        if it were in the tree.  Note that this will *NOT*
        be set if the search result is TableEmptyTree.

        Return Value:

        TABLE_SEARCH_RESULT - TableEmptyTree: The tree was empty.  NodeOrParent
        is *not* altered.

        TableFoundNode: A node with the key is in the tree.
        NodeOrParent points to that node.

        TableInsertAsLeft: Node with key was not found.
        NodeOrParent points to what would
        be parent.  The node would be the
        left child.

        TableInsertAsRight: Node with key was not found.
        NodeOrParent points to what would
        be parent.  The node would be
        the right child.

        Environment:

        Kernel mode.  The PFN lock is held for some of the tables.

        --*/

    {
        PMMADDRESS_NODE Child;
        PMMADDRESS_NODE NodeToExamine;
        PMMVAD_SHORT    VpnCompare;
        ULONG_PTR       startVpn;
        ULONG_PTR       endVpn;

        if (Table->NumberGenericTableElements == 0) {
            return TableEmptyTree;
        }

        NodeToExamine = (PMMADDRESS_NODE)GET_VAD_ROOT(Table);

        for (;;) {

            VpnCompare = (PMMVAD_SHORT)NodeToExamine;
            startVpn = VpnCompare->StartingVpn;
            endVpn = VpnCompare->EndingVpn;

#if defined( _WIN81_ ) || defined( _WIN10_ )
            startVpn |= (ULONG_PTR)VpnCompare->StartingVpnHigh << 32;
            endVpn |= (ULONG_PTR)VpnCompare->EndingVpnHigh << 32;
#endif  

            //
            // Compare the buffer with the key in the tree element.
            //

            if (StartingVpn < startVpn) {

                Child = NodeToExamine->LeftChild;

                if (Child != NULL) {
                    NodeToExamine = Child;
                }
                else {

                    //
                    // Node is not in the tree.  Set the output
                    // parameter to point to what would be its
                    // parent and return which child it would be.
                    //

                    *NodeOrParent = NodeToExamine;
                    return TableInsertAsLeft;
                }
            }
            else if (StartingVpn <= endVpn) {

                //
                // This is the node.
                //

                *NodeOrParent = NodeToExamine;
                return TableFoundNode;
            }
            else {

                Child = NodeToExamine->RightChild;

                if (Child != NULL) {
                    NodeToExamine = Child;
                }
                else {

                    //
                    // Node is not in the tree.  Set the output
                    // parameter to point to what would be its
                    // parent and return which child it would be.
                    //

                    *NodeOrParent = NodeToExamine;
                    return TableInsertAsRight;
                }
            }

        };
    }
}


/// <summary>
/// Find VAD that describes target address
/// </summary>
/// <param name="pProcess">Target process object</param>
/// <param name="address">Address to find</param>
/// <param name="pResult">Found VAD. NULL if not found</param>
/// <returns>Status code</returns>
NTSTATUS BBFindVAD(_In_ PEPROCESS pProcess, _In_ ULONG_PTR address, _Out_ win7::PMMVAD_SHORT * pResult)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR vpnStart = address >> PAGE_SHIFT;

    ASSERT(pProcess != NULL && pResult != NULL);
    if (pProcess == NULL || pResult == NULL)
        return STATUS_INVALID_PARAMETER;

    win7::PMM_AVL_TABLE pTable = (win7::PMM_AVL_TABLE)((PUCHAR)pProcess + 0x448/*dynData.VadRoot*/);
    win7::PMM_AVL_NODE pNode = win7::GET_VAD_ROOT(pTable);

    // Search VAD
    if (win7::MiFindNodeOrParent(pTable, vpnStart, &pNode) == TableFoundNode)
    {
        *pResult = (win7::PMMVAD_SHORT)pNode;
    }
    else
    {
        DbgPrint("BlackBone: %s: VAD entry for address 0x%p not found\n", __FUNCTION__, address);
        status = STATUS_NOT_FOUND;
    }

    return status;
}


/// <summary>
/// Find VAD that describes target address
/// </summary>
/// <param name="pProcess">Target process object</param>
/// <param name="address">Address to find</param>
/// <param name="pResult">Found VAD. NULL if not found</param>
/// <returns>Status code</returns>
NTSTATUS BBFindVAD(_In_ PEPROCESS pProcess, _In_ ULONG_PTR address, _Out_ win8::PMMVAD_SHORT * pResult)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR vpnStart = address >> PAGE_SHIFT;

    ASSERT(pProcess != NULL && pResult != NULL);
    if (pProcess == NULL || pResult == NULL)
        return STATUS_INVALID_PARAMETER;

    win8::PMM_AVL_TABLE pTable = (win8::PMM_AVL_TABLE)((PUCHAR)pProcess + 0x590 /*dynData.VadRoot*/);
    win8::PMM_AVL_NODE pNode = win8::GET_VAD_ROOT(pTable);

    // Search VAD
    if (win8::MiFindNodeOrParent(pTable, vpnStart, &pNode) == TableFoundNode)
    {
        *pResult = (win8::PMMVAD_SHORT)pNode;
    }
    else
    {
        DbgPrint("BlackBone: %s: VAD entry for address 0x%p not found\n", __FUNCTION__, address);
        status = STATUS_NOT_FOUND;
    }

    return status;
}

NTSTATUS SecureVAD(_Out_ win7::PMMVAD_LONG pLongVad)
{
    //
    // Setup VAD flags.
    //

    pLongVad->vad.vadShort.u.VadFlags.CommitCharge = MM_MAX_COMMIT::Windows7;
    pLongVad->vad.vadShort.u.VadFlags.NoChange = TRUE;

    pLongVad->vad.u2.VadFlags2.OneSecured = TRUE;
    pLongVad->vad.u2.VadFlags2.LongVad = TRUE;

    //
    // Make the entire range secure.
    //

    pLongVad->u3.Secured.u1.StartVa = reinterpret_cast<PVOID>(pLongVad->vad.vadShort.StartingVpn << PAGE_SHIFT);
    pLongVad->u3.Secured.EndVa = reinterpret_cast<PVOID>(((pLongVad->vad.vadShort.EndingVpn + 1) << PAGE_SHIFT) - 1);

    return STATUS_SUCCESS;
}

NTSTATUS SecureVAD(_Out_ win8::PMMVAD pVad)
{
    NTSTATUS status = STATUS_SUCCESS;

    //
    // Setup VAD flags.
    //

    pVad->Core.u.VadFlags.NoChange = TRUE;
    pVad->Core.u1.VadFlags1.CommitCharge = MM_MAX_COMMIT::Windows8;

    //
    // Setup the VAD event block, which contains the memory range to secure.
    //

    auto pVadEventBlock = static_cast<win8::PMI_VAD_EVENT_BLOCK>(
        ExAllocatePoolWithTag(NonPagedPool, sizeof(win8::MI_VAD_EVENT_BLOCK), VAD_EVENT_BLOCK_POOL_TAG));

    if (!pVadEventBlock) {
        DbgPrint("Failed to allocate long VAD event block, insufficient resources\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    pVadEventBlock->Next = nullptr;
    pVadEventBlock->WaitReason = 2; // kd> !poolfind -tag "MmSe" -x "dt nt!_MI_VAD_EVENT_BLOCK @$extret WaitReason"

    //
    // Make the entire range secure.
    //

    pVadEventBlock->SecureInfo.u1.StartVa = reinterpret_cast<PVOID>(pVad->Core.StartingVpn << PAGE_SHIFT);
    pVadEventBlock->SecureInfo.EndVa = reinterpret_cast<PVOID>(((pVad->Core.EndingVpn + 1) << PAGE_SHIFT) - 1);

    pVad->Core.EventList = pVadEventBlock;

Exit:
    return status;
}