$(document).ready(function() {
    // Hide the popup initially
    $("#popup-container").hide();
  
    // When the "Run Scan" button is clicked
    $("#run-script-btn").click(function() {
      // Get the values of the IP address and port number fields
      var ip = $("#ip-address").val();
      var port = $("#port-number").val();
      var add_to_db = $("#add-to-db").is(":checked");
  
      // Send an AJAX POST request to the /scan route with the IP address and port number data
      $.ajax({
        type: "POST",
        url: '/scan',
        data: {ip_address: ip, port_number: port, add_to_db: add_to_db},
        beforeSend: function() {
          // Show the popup before the request is sent
          $("#popup-container").show();
          $("#popup-result").html("Scanning...");
        },
        success: function(response) {
          console.log(response);
          if (response.report) {
            console.log(response.report);
            // Update the popup content with the scan results
            $("#popup-result").html(response.report);
          } else {
            console.log(response.error);
            $("#popup-result").html("An error occurred: " + response.error);
          }
        },
        error: function(xhr, status, error) {      
            // If an error occurs, display the error message in the popup
            console.log(error);
            $("#popup-result").html("An error occurred: " + error);
        },
        complete: function() {
            // Update the popup content when the request is complete
            $("#popup-result").prepend("<h2>Scan Complete</h2>");
        }
      });
    });
  
    // When the "Close" button is clicked, hide the popup
    $("#close-button").click(function() {
      $("#popup-container").hide();
    });
  });
  