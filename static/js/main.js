/**
 * ICSS India - Enhanced Main JavaScript File
 * Advanced Scroll Triggers, 3D Parallax, and Interactive Animations
 */

// ========== DOCUMENT READY ==========
document.addEventListener('DOMContentLoaded', function() {
    
    // Initialize all functions
    initScrollToTop();
    initSmoothScroll();
    initNavbarScroll();
    initMarqueeAnimation();
    initLazyLoading();
    initFormValidation();
    initScrollAnimations();
    initParallaxEffects();
    init3DCardEffects();
    initCounterAnimation();
    initCursorEffects();
    initTypingAnimation();
    initParticleBackground();
    
    console.log('ICSS India Enhanced Website Loaded Successfully!');
});

// ========== SCROLL TO TOP BUTTON ==========
function initScrollToTop() {
    const scrollTopBtn = document.getElementById('scrollTopBtn');
    
    if (scrollTopBtn) {
        // Show/hide button based on scroll position with smooth transition
        window.addEventListener('scroll', function() {
            if (window.pageYOffset > 300) {
                scrollTopBtn.classList.add('show');
            } else {
                scrollTopBtn.classList.remove('show');
            }
        });
        
        // Smooth scroll to top with easing
        scrollTopBtn.addEventListener('click', function() {
            const scrollToTop = () => {
                const currentScroll = window.pageYOffset;
                if (currentScroll > 0) {
                    window.requestAnimationFrame(scrollToTop);
                    window.scrollTo(0, currentScroll - currentScroll / 8);
                }
            };
            scrollToTop();
        });
    }
}

// ========== SMOOTH SCROLL FOR NAVIGATION LINKS ==========
function initSmoothScroll() {
    const navLinks = document.querySelectorAll('a[href^="#"]');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            const href = this.getAttribute('href');
            
            // Skip if it's just "#" or a Bootstrap toggle
            if (href === '#' || this.getAttribute('data-bs-toggle')) {
                return;
            }
            
            e.preventDefault();
            const target = document.querySelector(href);
            
            if (target) {
                const navbarHeight = document.querySelector('.navbar').offsetHeight;
                const targetPosition = target.offsetTop - navbarHeight - 20;
                
                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
                
                // Update active link
                navLinks.forEach(l => l.classList.remove('active'));
                this.classList.add('active');
            }
        });
    });
}

// ========== ENHANCED NAVBAR BEHAVIOR ON SCROLL ==========
function initNavbarScroll() {
    const navbar = document.querySelector('.navbar');
    let lastScroll = 0;
    
    window.addEventListener('scroll', function() {
        const currentScroll = window.pageYOffset;
        
        // Add shadow and background when scrolled
        if (currentScroll > 100) {
            navbar.classList.add('scrolled');
            navbar.style.transform = 'translateY(0)';
        } else {
            navbar.classList.remove('scrolled');
        }
        
        // Hide navbar on scroll down, show on scroll up
        if (currentScroll > lastScroll && currentScroll > 500) {
            navbar.style.transform = 'translateY(-100%)';
        } else {
            navbar.style.transform = 'translateY(0)';
        }
        
        lastScroll = currentScroll;
    });
}

// ========== ENHANCED MARQUEE ANIMATION ==========
function initMarqueeAnimation() {
    const marqueeContent = document.querySelector('.marquee-content');
    
    if (marqueeContent) {
        // Clone content for seamless loop
        const updateItems = marqueeContent.innerHTML;
        marqueeContent.innerHTML = updateItems + updateItems;
        
        // Pause on hover with smooth transition
        const marqueeContainer = document.querySelector('.updates-marquee');
        if (marqueeContainer) {
            marqueeContainer.addEventListener('mouseenter', function() {
                marqueeContent.style.animationPlayState = 'paused';
            });
            
            marqueeContainer.addEventListener('mouseleave', function() {
                marqueeContent.style.animationPlayState = 'running';
            });
        }
    }
}

// ========== ENHANCED LAZY LOADING FOR IMAGES ==========
function initLazyLoading() {
    if ('IntersectionObserver' in window) {
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    
                    // Fade in effect
                    img.style.opacity = '0';
                    img.style.transition = 'opacity 0.6s ease';
                    
                    img.src = img.dataset.src || img.src;
                    
                    img.onload = () => {
                        img.style.opacity = '1';
                        img.classList.add('loaded');
                    };
                    
                    observer.unobserve(img);
                }
            });
        }, {
            rootMargin: '50px 0px',
            threshold: 0.01
        });
        
        const images = document.querySelectorAll('img[data-src], img:not([data-src])');
        images.forEach(img => imageObserver.observe(img));
    }
}

// ========== FORM VALIDATION ==========
function initFormValidation() {
    const newsletterForm = document.querySelector('.newsletter-form');
    
    if (newsletterForm) {
        newsletterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const emailInput = this.querySelector('input[type="email"]');
            const email = emailInput.value.trim();
            
            if (validateEmail(email)) {
                // Animate button
                const btn = this.querySelector('.btn-subscribe');
                btn.innerHTML = '<i class="fas fa-check"></i> Subscribed!';
                btn.style.background = '#28a745';
                
                showNotification('Thank you for subscribing! 🎉', 'success');
                emailInput.value = '';
                
                setTimeout(() => {
                    btn.innerHTML = 'Subscribe';
                    btn.style.background = '';
                }, 3000);
            } else {
                showNotification('Please enter a valid email address', 'error');
                emailInput.classList.add('shake');
                setTimeout(() => emailInput.classList.remove('shake'), 500);
            }
        });
    }
}

// ========== EMAIL VALIDATION ==========
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// ========== ENHANCED NOTIFICATION SYSTEM ==========
function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existing = document.querySelector('.notification');
    if (existing) {
        existing.remove();
    }
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    
    const icons = {
        success: 'check-circle',
        error: 'exclamation-circle',
        info: 'info-circle'
    };
    
    const colors = {
        success: '#28a745',
        error: '#dc3545',
        info: '#17a2b8'
    };
    
    notification.innerHTML = `
        <i class="fas fa-${icons[type]}"></i>
        <span>${message}</span>
        <button class="notification-close">&times;</button>
    `;
    
    // Add styles
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: -400px;
        background: ${colors[type]};
        color: white;
        padding: 15px 25px;
        border-radius: 10px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        z-index: 10000;
        display: flex;
        align-items: center;
        gap: 12px;
        min-width: 300px;
        animation: slideInRight 0.5s ease forwards;
        backdrop-filter: blur(10px);
    `;
    
    document.body.appendChild(notification);
    
    // Close button functionality
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.style.cssText = `
        background: transparent;
        border: none;
        color: white;
        font-size: 24px;
        cursor: pointer;
        margin-left: auto;
        opacity: 0.8;
        transition: opacity 0.3s;
    `;
    
    closeBtn.addEventListener('mouseenter', () => closeBtn.style.opacity = '1');
    closeBtn.addEventListener('mouseleave', () => closeBtn.style.opacity = '0.8');
    closeBtn.addEventListener('click', () => removeNotification(notification));
    
    // Remove after 5 seconds
    setTimeout(() => removeNotification(notification), 5000);
}

function removeNotification(notification) {
    notification.style.animation = 'slideOutRight 0.5s ease forwards';
    setTimeout(() => notification.remove(), 500);
}

// ========== ADVANCED SCROLL ANIMATIONS ==========
function initScrollAnimations() {
    const observerOptions = {
        threshold: 0.15,
        rootMargin: '0px 0px -100px 0px'
    };
    
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                // Add stagger effect
                setTimeout(() => {
                    entry.target.classList.add('visible');
                    entry.target.classList.add('animated');
                }, index * 100);
            }
        });
    }, observerOptions);
    
    // Observe different animation types
    const fadeInElements = document.querySelectorAll('.fade-in-up, .fade-in-left, .fade-in-right, .scale-in, .rotate-in');
    fadeInElements.forEach(el => {
        observer.observe(el);
    });
    
    // Observe cards and sections
    const cards = document.querySelectorAll('.card, .course-card, .blog-card, .team-card');
    cards.forEach((card, index) => {
        card.classList.add('fade-in-up');
        card.classList.add(`stagger-${(index % 6) + 1}`);
        observer.observe(card);
    });
    
    // Observe section titles
    const titles = document.querySelectorAll('.section-title');
    titles.forEach(title => {
        title.classList.add('fade-in-up');
        observer.observe(title);
    });
}

// ========== 3D PARALLAX EFFECTS ==========
function initParallaxEffects() {
    const parallaxElements = document.querySelectorAll('.parallax-layer, .floating-shape');
    
    window.addEventListener('scroll', () => {
        const scrolled = window.pageYOffset;
        
        parallaxElements.forEach((element, index) => {
            const speed = 0.5 + (index * 0.1);
            const yPos = -(scrolled * speed);
            element.style.transform = `translate3d(0, ${yPos}px, 0)`;
        });
    });
    
    // Mouse move parallax effect
    document.addEventListener('mousemove', (e) => {
        const mouseX = e.clientX / window.innerWidth - 0.5;
        const mouseY = e.clientY / window.innerHeight - 0.5;
        
        parallaxElements.forEach((element, index) => {
            const speed = 20 + (index * 10);
            const x = mouseX * speed;
            const y = mouseY * speed;
            
            element.style.transform = `translate3d(${x}px, ${y}px, 0)`;
        });
    });
}

// ========== 3D CARD TILT EFFECTS ==========
function init3DCardEffects() {
    const cards = document.querySelectorAll('.card, .course-card');
    
    cards.forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;
            
            const rotateX = (y - centerY) / 10;
            const rotateY = (centerX - x) / 10;
            
            card.style.transform = `
                perspective(1000px)
                rotateX(${rotateX}deg)
                rotateY(${rotateY}deg)
                translateY(-10px)
                scale(1.02)
            `;
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) translateY(0) scale(1)';
        });
    });
}

// ========== ANIMATED COUNTER FOR STATISTICS ==========
function initCounterAnimation() {
    const counters = document.querySelectorAll('.stat-number');
    const speed = 200;
    
    const observerOptions = {
        threshold: 0.5
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const counter = entry.target;
                const target = parseInt(counter.getAttribute('data-target') || counter.innerText.replace(/[^0-9]/g, ''));
                
                const updateCount = () => {
                    const count = parseInt(counter.innerText.replace(/[^0-9]/g, '') || 0);
                    const increment = target / speed;
                    
                    if (count < target) {
                        counter.innerText = Math.ceil(count + increment) + (counter.innerText.includes('+') ? '+' : '') + (counter.innerText.includes('%') ? '%' : '');
                        setTimeout(updateCount, 1);
                    } else {
                        counter.innerText = target + (counter.innerText.includes('+') ? '+' : '') + (counter.innerText.includes('%') ? '%' : '');
                    }
                };
                
                updateCount();
                observer.unobserve(counter);
            }
        });
    }, observerOptions);
    
    counters.forEach(counter => {
        observer.observe(counter);
    });
}

// ========== CUSTOM CURSOR EFFECTS ==========
function initCursorEffects() {
    // Only on desktop
    if (window.innerWidth > 768) {
        const cursorDot = document.createElement('div');
        cursorDot.className = 'cursor-dot';
        document.body.appendChild(cursorDot);
        
        const cursorOutline = document.createElement('div');
        cursorOutline.className = 'cursor-outline';
        document.body.appendChild(cursorOutline);
        
        let mouseX = 0, mouseY = 0;
        let outlineX = 0, outlineY = 0;
        
        document.addEventListener('mousemove', (e) => {
            mouseX = e.clientX;
            mouseY = e.clientY;
            
            cursorDot.style.left = mouseX + 'px';
            cursorDot.style.top = mouseY + 'px';
        });
        
        // Smooth outline following
        const animateOutline = () => {
            outlineX += (mouseX - outlineX) * 0.15;
            outlineY += (mouseY - outlineY) * 0.15;
            
            cursorOutline.style.left = outlineX + 'px';
            cursorOutline.style.top = outlineY + 'px';
            
            requestAnimationFrame(animateOutline);
        };
        
        animateOutline();
        
        // Expand cursor on clickable elements
        const clickableElements = document.querySelectorAll('a, button, .btn, input, textarea, select');
        
        clickableElements.forEach(el => {
            el.addEventListener('mouseenter', () => {
                cursorOutline.style.width = '50px';
                cursorOutline.style.height = '50px';
                cursorDot.style.transform = 'scale(1.5)';
            });
            
            el.addEventListener('mouseleave', () => {
                cursorOutline.style.width = '30px';
                cursorOutline.style.height = '30px';
                cursorDot.style.transform = 'scale(1)';
            });
        });
    }
}

// ========== TYPING ANIMATION FOR HERO TEXT ==========
function initTypingAnimation() {
    const typingElements = document.querySelectorAll('[data-typing]');
    
    typingElements.forEach(element => {
        const text = element.innerText;
        element.innerText = '';
        element.style.borderRight = '2px solid var(--gold)';
        
        let index = 0;
        
        const typeWriter = () => {
            if (index < text.length) {
                element.innerText += text.charAt(index);
                index++;
                setTimeout(typeWriter, 50);
            } else {
                // Remove cursor after typing
                setTimeout(() => {
                    element.style.borderRight = 'none';
                }, 500);
            }
        };
        
        // Start typing when element is in view
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    typeWriter();
                    observer.unobserve(entry.target);
                }
            });
        });
        
        observer.observe(element);
    });
}

// ========== PARTICLE BACKGROUND ANIMATION ==========
function initParticleBackground() {
    const canvas = document.createElement('canvas');
    canvas.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        pointer-events: none;
        z-index: 0;
        opacity: 0.3;
    `;
    document.body.insertBefore(canvas, document.body.firstChild);
    
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const particles = [];
    const particleCount = 50;
    
    class Particle {
        constructor() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.size = Math.random() * 3 + 1;
            this.speedX = Math.random() * 0.5 - 0.25;
            this.speedY = Math.random() * 0.5 - 0.25;
            this.color = Math.random() > 0.5 ? 'rgba(255, 215, 0, 0.5)' : 'rgba(0, 51, 102, 0.5)';
        }
        
        update() {
            this.x += this.speedX;
            this.y += this.speedY;
            
            if (this.x > canvas.width) this.x = 0;
            if (this.x < 0) this.x = canvas.width;
            if (this.y > canvas.height) this.y = 0;
            if (this.y < 0) this.y = canvas.height;
        }
        
        draw() {
            ctx.fillStyle = this.color;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();
        }
    }
    
    for (let i = 0; i < particleCount; i++) {
        particles.push(new Particle());
    }
    
    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        particles.forEach(particle => {
            particle.update();
            particle.draw();
        });
        
        // Connect particles
        particles.forEach((a, i) => {
            particles.slice(i + 1).forEach(b => {
                const dx = a.x - b.x;
                const dy = a.y - b.y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                
                if (distance < 150) {
                    ctx.strokeStyle = `rgba(255, 215, 0, ${1 - distance / 150})`;
                    ctx.lineWidth = 0.5;
                    ctx.beginPath();
                    ctx.moveTo(a.x, a.y);
                    ctx.lineTo(b.x, b.y);
                    ctx.stroke();
                }
            });
        });
        
        requestAnimationFrame(animate);
    }
    
    animate();
    
    // Resize canvas on window resize
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// ========== PERFORMANCE MONITORING ==========
if (window.performance) {
    window.addEventListener('load', function() {
        setTimeout(function() {
            const perfData = window.performance.timing;
            const pageLoadTime = perfData.loadEventEnd - perfData.navigationStart;
            console.log(`%cPage Load Time: ${pageLoadTime}ms`, 'color: #FFD700; font-weight: bold; font-size: 14px;');
        }, 0);
    });
}

// ========== AUTO-ADVANCE CAROUSEL WITH ENHANCED TRANSITIONS ==========
document.addEventListener('DOMContentLoaded', function() {
    const heroCarousel = document.getElementById('heroCarousel');
    if (heroCarousel) {
        const carousel = new bootstrap.Carousel(heroCarousel, {
            interval: 5000,
            wrap: true,
            pause: 'hover',
            touch: true
        });
        
        // Add custom transition effects
        heroCarousel.addEventListener('slide.bs.carousel', (e) => {
            const activeItem = e.relatedTarget;
            activeItem.style.animation = 'fadeInZoom 0.8s ease';
        });
    }
});

// ========== ENHANCED CARD HOVER EFFECTS ==========
document.addEventListener('DOMContentLoaded', function() {
    const courseCards = document.querySelectorAll('.course-card, .course-catalogue-card, .blog-card');
    
    courseCards.forEach(card => {
        // Add shimmer effect on hover
        card.addEventListener('mouseenter', function() {
            const shimmer = document.createElement('div');
            shimmer.style.cssText = `
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3), transparent);
                pointer-events: none;
                animation: shimmer 1.5s ease;
            `;
            this.appendChild(shimmer);
            
            setTimeout(() => shimmer.remove(), 1500);
        });
    });
});

// ========== LOADING SCREEN ==========
window.addEventListener('load', function() {
    const loadingOverlay = document.querySelector('.loading-overlay');
    if (loadingOverlay) {
        setTimeout(() => {
            loadingOverlay.style.opacity = '0';
            setTimeout(() => loadingOverlay.remove(), 500);
        }, 1500);
    }
});

// ========== MOBILE MENU ENHANCEMENTS ==========
document.querySelectorAll('.navbar-nav .nav-link').forEach(link => {
    link.addEventListener('click', function() {
        const navbarCollapse = document.querySelector('.navbar-collapse');
        if (navbarCollapse && navbarCollapse.classList.contains('show')) {
            const bsCollapse = new bootstrap.Collapse(navbarCollapse);
            bsCollapse.hide();
        }
    });
});

// ========== COURSE ENROLLMENT HANDLERS ==========
document.querySelectorAll('.btn-course, .btn-primary').forEach(button => {
    button.addEventListener('click', function(e) {
        if (this.classList.contains('btn-course')) {
            e.preventDefault();
            const courseName = this.closest('.card, .course-card')?.querySelector('h4, h5')?.textContent || 'this course';
            showNotification(`Thank you for your interest in ${courseName}! 🎓`, 'success');
        }
    });
});

// ========== ANIMATED SECTION BACKGROUNDS ==========
function initSectionBackgrounds() {
    const sections = document.querySelectorAll('section');
    
    sections.forEach((section, index) => {
        if (index % 2 === 0) {
            const bgAnimation = document.createElement('div');
            bgAnimation.style.cssText = `
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: radial-gradient(circle at ${Math.random() * 100}% ${Math.random() * 100}%, rgba(255, 215, 0, 0.05) 0%, transparent 50%);
                pointer-events: none;
                animation: moveGradient 15s ease-in-out infinite;
            `;
            section.style.position = 'relative';
            section.insertBefore(bgAnimation, section.firstChild);
        }
    });
}

// Initialize section backgrounds
document.addEventListener('DOMContentLoaded', initSectionBackgrounds);

// ========== ADD CSS ANIMATIONS ==========
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeInZoom {
        from {
            opacity: 0;
            transform: scale(0.95);
        }
        to {
            opacity: 1;
            transform: scale(1);
        }
    }
    
    @keyframes shimmer {
        from {
            left: -100%;
        }
        to {
            left: 100%;
        }
    }
    
    @keyframes moveGradient {
        0%, 100% {
            transform: translate(0, 0) scale(1);
        }
        50% {
            transform: translate(20px, 20px) scale(1.1);
        }
    }
    
    @keyframes slideInRight {
        from {
            right: -400px;
        }
        to {
            right: 20px;
        }
    }
    
    @keyframes slideOutRight {
        from {
            right: 20px;
        }
        to {
            right: -400px;
        }
    }
    
    .shake {
        animation: shake 0.5s;
    }
    
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-10px); }
        75% { transform: translateX(10px); }
    }
`;
document.head.appendChild(style);

console.log('%c🚀 ICSS India - Powered by Advanced Animations & 3D Effects', 'color: #FFD700; font-size: 16px; font-weight: bold; background: #003366; padding: 10px; border-radius: 5px;');
