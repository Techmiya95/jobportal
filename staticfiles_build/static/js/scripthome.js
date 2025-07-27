$(document).on('click', '.generate-resume-btn', function() {
    const templateId = $(this).closest('.template-preview').data('template');
    const btn = $(this);
    
    // Show loading state
    btn.html('<i class="fas fa-spinner fa-spin"></i> Preparing...');
    btn.prop('disabled', true);
    
    // Fetch user data including experiences and projects
    $.ajax({
        url: '/generate_resume/' + templateId + '/',
        method: 'GET',
        success: function(response) {
            if (response.success) {
                // Get the full user data including experiences and projects
                const userId = "{{ request.user.id }}";
                
                // First get experiences
                $.ajax({
                    url: '/get_experiences/',
                    method: 'GET',
                    data: { user_id: userId },
                    success: function(expResponse) {
                        if (expResponse.success) {
                            // Then get projects
                            $.ajax({
                                url: '/get_projects/',
                                method: 'GET',
                                data: { user_id: userId },
                                success: function(projResponse) {
                                    if (projResponse.success) {
                                        // Combine all data
                                        const fullUserData = {
                                            ...response.data[0],
                                            experiences: expResponse.data,
                                            projects: projResponse.data
                                        };
                                        
                                        // Generate PDF with the complete user data
                                        generateResumeWithJsPDF(templateId, fullUserData);
                                    } else {
                                        alert('Error: Could not fetch projects');
                                    }
                                },
                                error: function() {
                                    alert('Error fetching projects');
                                },
                                complete: function() {
                                    // Reset button state
                                    btn.html('Use Template ' + templateId);
                                    btn.prop('disabled', false);
                                }
                            });
                        } else {
                            alert('Error: Could not fetch experiences');
                        }
                    },
                    error: function() {
                        alert('Error fetching experiences');
                    }
                });
            } else {
                alert('Error: Could not fetch user data');
            }
        },
        error: function(xhr, status, error) {
            alert('Error: ' + error);
            // Reset button state
            btn.html('Use Template ' + templateId);
            btn.prop('disabled', false);
        }
    });
});