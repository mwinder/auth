using System.Web.Http;

namespace TokenAuth.Controllers
{
    [Authorize]
    public class SecuredController : ApiController
    {
        public IHttpActionResult Get()
        {
            return Ok(new { status = "SUCCESS" });
        }
    }
}
