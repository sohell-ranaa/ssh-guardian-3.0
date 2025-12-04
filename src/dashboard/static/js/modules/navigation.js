document.querySelectorAll('.nav-item[data-submenu]').forEach(item => {
            item.addEventListener('click', (e) => {
                const submenuId = 'submenu-' + item.dataset.submenu;
                const submenu = document.getElementById(submenuId);

                item.classList.toggle('expanded');
                submenu.classList.toggle('show');
            });