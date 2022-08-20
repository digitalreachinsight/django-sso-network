
def template_variables(request):
    variables_hash = {}
    variables_hash['request'] = request
    print ("LOADING")

    return variables_hash
