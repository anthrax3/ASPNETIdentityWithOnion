using System.Threading.Tasks;
using System.Web.Mvc;
using ASPNETIdentityWithOnion.Core.DomainModels;
using MediatR;
using ASPNETIdentityWithOnion.Core.Query;

namespace ASPNETIdentityWithOnion.Web.Controllers
{
    public class ProductController : Controller
    {
        private readonly IMediator _mediator;

        public ProductController(IMediator mediator)
        {
            _mediator = mediator;
        }
        
        public async Task<ActionResult> Index()
        {
            var list = _mediator.Send(new GenericQuery<Product>());
            //var test3 = _mediator.Send(new AutoMapperQuery<Product,ProductDto>());

            return View(list);
        }
	}
}