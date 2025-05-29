// Token Creator JavaScript

/**
 * Load all wallets from the API for the token creator page
 */
function loadWallets() {
    var walletSelector = document.getElementById('wallet-selector');
    
    // Show loading state
    walletSelector.innerHTML = '<option value="" selected disabled>Cüzdanlar yükleniyor...</option>';
    walletSelector.disabled = true;
    
    // Get wallets from API
    fetch('/api/wallets')
    .then(function(response) {
        return response.json();
    })
    .then(function(data) {
        walletSelector.disabled = false;
        
        if (data.success && data.data && data.data.length > 0) {
            walletSelector.innerHTML = '<option value="" selected disabled>Cüzdan seçin</option>';
            
            // Add wallets to select
            for (var i = 0; i < data.data.length; i++) {
                var wallet = data.data[i];
                var option = document.createElement('option');
                option.value = wallet.id;
                
                // Get shortened address with first 7 and last 5 chars
                var shortAddress = wallet.public_key.substring(0, 7) + '...' + 
                                 wallet.public_key.substring(wallet.public_key.length - 5);
                
                // Add balance info
                if (wallet.balance !== undefined) {
                    option.textContent = shortAddress + ' (' + wallet.balance.toFixed(4) + ' SOL)';
                } else {
                    option.textContent = shortAddress;
                }
                
                walletSelector.appendChild(option);
            }
        } else {
            walletSelector.innerHTML = '<option value="" selected disabled>Cüzdan bulunamadı</option>';
            console.warn('Wallet bulunamadı');
        }
    })
    .catch(function(error) {
        walletSelector.innerHTML = '<option value="" selected disabled>Cüzdanlar yüklenemedi</option>';
        walletSelector.disabled = false;
        console.warn('Wallet yükleme hatası:', error);
    });
}

/**
 * Load user tokens from the API
 */
function loadTokens() {
    fetch('/api/tokens')
    .then(function(response) {
        return response.json();
    })
    .then(function(data) {
        if (data.success && data.data) {
            var tokenList = document.getElementById('token-list');
            
            // Clear existing rows
            tokenList.innerHTML = '';
            
            if (data.data.length === 0) {
                tokenList.innerHTML = '<tr><td colspan="4" class="text-center">Henüz token oluşturmadınız.</td></tr>';
                return;
            }
            
            // Add tokens to table
            for (var i = 0; i < data.data.length; i++) {
                var token = data.data[i];
                var row = document.createElement('tr');
                
                // Format token address for display
                var shortAddress = token.address.substring(0, 8) + '...' + token.address.substring(token.address.length - 8);
                
                row.innerHTML = `
                    <td>
                        <div class="d-flex align-items-center">
                            <div class="token-logo me-2">
                                <img src="/token-icon/${token.address}" alt="${token.symbol}" onerror="this.src='/static/img/token-placeholder.png'">
                            </div>
                            <div>
                                <div class="fw-bold">${token.name}</div>
                                <div class="small">${token.symbol}</div>
                            </div>
                        </div>
                    </td>
                    <td><div class="text-truncate token-address">${shortAddress}</div></td>
                    <td>${token.network}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary copy-address" data-address="${token.address}">
                            <i class="bi bi-clipboard"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-info view-token" data-address="${token.address}">
                            <i class="bi bi-eye"></i>
                        </button>
                    </td>
                `;
                
                tokenList.appendChild(row);
            }
            
            // Add click handlers for copy buttons
            var copyButtons = document.querySelectorAll('.copy-address');
            for (var i = 0; i < copyButtons.length; i++) {
                copyButtons[i].addEventListener('click', function(e) {
                    var address = this.getAttribute('data-address');
                    copyToClipboard(address);
                });
            }
            
            // Add click handlers for view buttons
            var viewButtons = document.querySelectorAll('.view-token');
            for (var i = 0; i < viewButtons.length; i++) {
                viewButtons[i].addEventListener('click', function(e) {
                    var address = this.getAttribute('data-address');
                    viewTokenDetails(address);
                });
            }
        } else {
            console.error('Failed to load tokens');
        }
    })
    .catch(function(error) {
        console.error('Error loading tokens:', error);
    });
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        alert('Token adresi panoya kopyalandı!');
    }).catch(function(err) {
        console.error('Failed to copy text: ', err);
    });
}

/**
 * View token details
 */
function viewTokenDetails(address) {
    alert('Token detayları yakında burada görüntülenecek: ' + address);
}

// Initialize token creator page when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Token icon upload and preview functionality
    var tokenIcon = document.getElementById('token-icon');
    var iconPreviewContainer = document.getElementById('icon-preview-container');
    var iconPreview = document.getElementById('icon-preview');
    var removeIconBtn = document.getElementById('remove-icon');
    
    if (tokenIcon) {
        tokenIcon.addEventListener('change', function(event) {
            var file = event.target.files[0];
            if (file) {
                var reader = new FileReader();
                reader.onload = function(e) {
                    iconPreview.src = e.target.result;
                    iconPreviewContainer.classList.remove('d-none');
                };
                reader.readAsDataURL(file);
            }
        });
    }
    
    if (removeIconBtn) {
        removeIconBtn.addEventListener('click', function() {
            tokenIcon.value = '';
            iconPreview.src = '';
            iconPreviewContainer.classList.add('d-none');
        });
    }
    
    // Token feature toggles
    var featureToggles = document.querySelectorAll('.feature-toggle');
    for (var i = 0; i < featureToggles.length; i++) {
        featureToggles[i].addEventListener('change', function() {
            var targetId = this.getAttribute('data-target');
            var target = document.getElementById(targetId);
            
            if (target) {
                if (this.checked) {
                    target.classList.remove('d-none');
                } else {
                    target.classList.add('d-none');
                }
            }
        });
    }
    
    // Load wallets for token creator
    loadWalletsForTokenCreator();
});