"""
TODO:
- We are checking access to studies atm, and not access to projects, because we
don't know which project a study belongs to. This causes duplicate authz
information in the user.yaml. Kind of hacky option: we could query peregrine -
if the user can see the study in peregrine, then they have "read" access to
the project. Or we could query the sheepdog DB directly.
- When using the Orthanc UI to upload files, this plugin is causing a "failed
csrf check" error. But we can still upload using the API.
"""


from cachelib import SimpleCache
from cdislogging import get_logger
from gen3authz.client.arborist.client import ArboristClient
import orthanc


# Cache the access for 1 second so that we don't make multiple requests to
# Arborist when a user accesses a webpage and fetches multiple JS/CSS files.
ACCESS_CACHE = SimpleCache(default_timeout=1)


def get_user_jwt(request):
    """
    Get the JWT from the request headers. If no JWT is provided, only public
    data will be available.
    """
    user_jwt = request.get("headers", {}).get("access_token")
    if not user_jwt:
        user_jwt_parts = request.get("headers", {}).get("authorization", "").split(" ")
        user_jwt = user_jwt_parts[1] if len(user_jwt_parts) > 1 else None
    return user_jwt


def authorize_user(jwt, service, method, resource):
    """
    Return True if the user is authorized to access the resource, False
    otherwise. If the access is not already cached, ask Arborist.
    """
    cache_key = f"{jwt}_{method}_{resource}"
    if ACCESS_CACHE.has(cache_key):
        authorized = ACCESS_CACHE.get(cache_key)
    else:
        authorized = arborist_client.auth_request(
            jwt=jwt,
            service=service,
            methods=[method],
            resources=[resource],
        )
        ACCESS_CACHE.set(cache_key, authorized)
    return authorized


def check_authorization(uri, **request):
    """
    Return True if the user is authorized to access the URI, False otherwise.
    """
    service = "dicom-viewer"
    resource = ""
    method = ""

    if uri == "/system":  # endpoint used by k8s healthcheck probes
        logger.debug("Accessing /system")
        return True

    if uri == "/dicom-web/studies" or uri.startswith("/dicom-web/studies/"):
        study_id = None
        if uri == "/dicom-web/studies":  # Ohif viewer V3
            study_id = request.get("get", {}).get("StudyInstanceUID")
        else:  # Ohif viewer V2 and V3
            try:
                study_id = uri.split("/")[3]
            except IndexError:
                logger.error(f"Unable to parse study ID from URI: {uri}. Denying access")
                return False
        if study_id:
            logger.debug(f"User accessing study: {study_id} (URI: {uri})")
            resource = f"/services/dicom-viewer/studies/{study_id}"
        else:
            resource = "/services/dicom-viewer/studies"
        method = "read"
    else:
        logger.debug(f"By default, admin access is required to access {uri}")
        resource = "/services/dicom-viewer"
        method = "create"

    authorized = authorize_user(
        jwt=get_user_jwt(request),
        service=service,
        method=method,
        resource=resource,
    )
    if not authorized:
        logger.error(
            f"Authorization error: user must have '{method}' access on '{resource}' for service '{service}'"
        )
    return authorized


logger = get_logger("authz-filter", log_level="debug")
arborist_client = ArboristClient(logger=logger)

logger.info("Registering Python plugin authorization filter")
orthanc.RegisterIncomingHttpRequestFilter(check_authorization)
