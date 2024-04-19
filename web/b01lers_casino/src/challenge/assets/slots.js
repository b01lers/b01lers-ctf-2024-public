document.addEventListener('DOMContentLoaded', function () {
    const images = ['skull.jpg', 'coin.jpg', 'logo_no_text.png', 'fake-b01lers.png', 'vr.png'];

    const rollButton = document.getElementById('roll-btn');
    const slots = document.querySelectorAll('.slot');

    let rolling = false;

    rollButton.addEventListener('click', function () {
        if (!rolling) {
            rolling = true;
            rollButton.disabled = true;

            let iterations = 0;
            const interval = setInterval(function () {
                iterations++;
                slots.forEach(slot => {
                    const randomIndex = Math.floor(Math.random() * images.length);
                    const randomImage = images[randomIndex];
                    slot.style.backgroundImage = `url('/static/${randomImage}')`;
                });

                if (iterations >= 50) {
                    clearInterval(interval);
                    checkWin();
                }
            }, 100);
        }
    });

    function checkWin() {
        const firstImage = slots[0].style.backgroundImage;
        const win = [...slots].every(slot => slot.style.backgroundImage === firstImage);

        if (win) {
            alert("You Gained $100");
            sendData({ change: 100 });
        } else {
            alert("You Lost $100");
            sendData({ change: -100 });
        }

        rolling = false;
        rollButton.disabled = false;
    }

    function sendData(data) {
        const cookies = document.cookie;
        fetch('/slots', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Cookie': cookies  // Set the cookie in the request headers
            },
            body: JSON.stringify(data)
        }).then(response => {
            // Handle response if needed
        }).catch(error => {
            console.error('Error:', error);
        });
    }
});