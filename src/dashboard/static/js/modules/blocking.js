async function loadBlocks() {
            const blockSource = document.getElementById('blockSourceFilter').value;
            const isActive = document.getElementById('blockStatusFilter').value;

            const params = new URLSearchParams({
                limit: blocksPageSize,
                offset: currentBlocksPage * blocksPageSize
            }

async function quickBlock(ipAddress, reason) {
            if (!confirm(`Block IP ${ipAddress}

async function quickUnblock(ipAddress) {
            if (!confirm(`Unblock IP ${ipAddress}