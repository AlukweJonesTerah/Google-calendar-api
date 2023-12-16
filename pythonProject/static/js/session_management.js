// Periodically send a heartbeat or ping to the server to indicate that the user is still active.
function sendHearbeat(){
    $.ajax({
        url: '/heartbeat',
        method: 'POST',
        success: function(response) {
             // Handle success based on the server's response
            if (response.status === 'success'){
                console.log('Heartbeat successful');
            }else {
                console.error('Heartbeat failed:', response.message);
            }
        },
        error: function(error) {
            console.error('Heartbeat failed:', error)
        }
    });
}

// Trigger heartbeat every 5 seconds
setInterval(sendHearbeat, 5000) // 5 * 60 * 1000 = 5 mins

// Handle window unload event when the user is navigating away from the page or closing the browser tab/window
$(window).on('beforeunload', function() {
    // Notify the server about the user leaving using navigator.sendBeacon
    navigator.sendBeacon('/leave-site');

    // Make an additional synchronous AJAX request to get a response (if needed)
    $.ajax({
        url: '/leave-site',
        method: 'POST',
        async: false, // Ensure the request is synchronous
        success: function(response){
            // Handle success based on the server's response
            if (response.status === 'success'){
                console.log('Leave site notification successful');
            } else {
                console.error('Leave site notification failed:', response.message);
            }
        },
        error: function(error){
            console.error('Leaving site notification failed:', error);
        }
    });
});
