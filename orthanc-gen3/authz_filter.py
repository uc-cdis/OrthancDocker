"""
TODO:
- we are checking access to studies atm, and not access to projects, because we don't know which project a study belongs to. This causes duplicate authz information in the user.yaml. We could query peregrine? if the user can see the study in peregrine, then they have "read" access.
- replace viewer error message "Failed to retrieve study data" with a message about access.
- fix for anonymous users to access public data (arborist error: "auth request missing auth header").
- 1 second cache for arborist requests? accessing /dicom-server creates many requests to arborist, for each JS/CSS file.
- this is causing "failed csrf check" error for the server upload page.
"""


from cdislogging import get_logger
from gen3authz.client.arborist.client import ArboristClient
import orthanc


logger = get_logger("authz-filter", log_level="debug")
arborist_client = ArboristClient(logger=logger)


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


def check_authorization(uri, **request):
    """
    Return True if the user is authorized to access the URI, False otherwise.
    """
    service = "dicom-viewer"
    resource = ""
    method = ""

    if uri.startswith("/dicom-web/studies/"):
        try:
            study_id = uri.split("/")[3]
        except IndexError:
            logger.error(f"Unable to parse study ID from URI: {uri}. Denying access")
            return False
        logger.debug(f"User accessing study: {study_id} (URI: {uri})")
        resource = f"/services/dicom-viewer/studies/{study_id}"
        method = "read"
    else:
        logger.debug(f"By default, admin access is required to access {uri}")
        resource = "/services/dicom-viewer"
        method = "write"

    authorized = arborist_client.auth_request(
        jwt=get_user_jwt(request),
        service=service,
        methods=[method],
        resources=[resource],
    )
    if not authorized:
        logger.error(
            f"Authorization error: user must have '{method}' access on '{resource}' for service '{service}'"
        )
    return authorized


logger.info("Registering Python plugin authorization filter")
orthanc.RegisterIncomingHttpRequestFilter(check_authorization)
