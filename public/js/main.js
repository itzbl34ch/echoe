document.addEventListener('DOMContentLoaded', () => {
    const themeIcon = document.getElementById('theme-icon');
    const body = document.body;
  
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        body.classList.add(savedTheme);
        
        if (savedTheme === 'dark-mode') {
            themeIcon.src = '/img/light-mode.png';
        } else {
            themeIcon.src = '/img/dark-mode.png';
        }
    }
  
    themeIcon.addEventListener('click', () => {
        if (body.classList.contains('light-mode')) {
            body.classList.remove('light-mode');
            body.classList.add('dark-mode');
            localStorage.setItem('theme', 'dark-mode');
            themeIcon.src = '/img/light-mode.png';
        } else {
            body.classList.remove('dark-mode');
            body.classList.add('light-mode');
            localStorage.setItem('theme', 'light-mode');
            themeIcon.src = '/img/dark-mode.png';
        }
    });
  });