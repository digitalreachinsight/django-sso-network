from django.conf import settings

def template_variables(request):
    variables_hash = {}
    variables_hash['request'] = request
    variables_hash['settings'] = settings
    print ("LOADING")

    return variables_hash
